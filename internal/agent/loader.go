package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Runtime struct {
	Collection     *ebpf.Collection
	Program        *ebpf.Program
	Link           link.Link
	AttachMode     string
	ObjectChecksum string
	Snapshot       LastValidSnapshot
}

type ProgramMetadata struct {
	ObjectChecksum          string `json:"object_checksum"`
	PreviousProgramChecksum string `json:"previous_program_checksum,omitempty"`
	ProgramName             string `json:"program_name"`
	InterfaceName           string `json:"interface_name"`
	InterfaceIndex          int    `json:"interface_index"`
	AttachMode              string `json:"attach_mode"`
	AttachedAt              string `json:"attached_at"`
}

func LoadAndAttach(cfg Config, metrics *Metrics, logger *slog.Logger) (*Runtime, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	if err := ensureRuntimeDirs(cfg); err != nil {
		return nil, err
	}

	objectChecksum, err := FileSHA256(cfg.XDPObject)
	if err != nil {
		return nil, fmt.Errorf("hash XDP object: %w", err)
	}
	if metrics != nil {
		metrics.SetObjectChecksum(objectChecksum)
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.XDPObject)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	if err := ValidateCollectionSpec(spec); err != nil {
		return nil, err
	}
	EnableMapPinning(spec)

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: cfg.MapPinDir()},
	})
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	rt := &Runtime{
		Collection:     coll,
		Program:        coll.Programs["xdp_entry"],
		ObjectChecksum: objectChecksum,
	}
	if rt.Program == nil {
		coll.Close()
		return nil, fmt.Errorf("xdp_entry program not loaded")
	}

	snapshot, err := loadOrCreateSnapshot(cfg.SnapshotPath, objectChecksum, logger)
	if err != nil {
		coll.Close()
		return nil, err
	}
	rt.Snapshot = snapshot
	if err := seedRuntimeConfig(coll.Maps["runtime_config"], snapshot.RuntimeConfig(time.Now())); err != nil {
		coll.Close()
		return nil, err
	}
	if metrics != nil {
		metrics.SetSnapshotVersion(snapshot.PolicyVersion)
	}

	if err := os.Remove(cfg.ProgramPinPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		coll.Close()
		return nil, fmt.Errorf("remove stale program pin: %w", err)
	}
	if err := rt.Program.Pin(cfg.ProgramPinPath()); err != nil {
		coll.Close()
		return nil, fmt.Errorf("pin program: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.WANIface)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("lookup interface %s: %w", cfg.WANIface, err)
	}

	xdpLink, mode, err := attachOrUpdateLink(cfg, rt.Program, iface.Index, metrics, logger)
	if err != nil {
		coll.Close()
		return nil, err
	}
	rt.Link = xdpLink
	rt.AttachMode = mode
	if metrics != nil {
		metrics.SetXDPMode(mode)
	}

	previousMetadata, _ := loadMetadata(cfg.MetadataPath())
	metadata := ProgramMetadata{
		ObjectChecksum: objectChecksum,
		ProgramName:    "xdp_entry",
		InterfaceName:  iface.Name,
		InterfaceIndex: iface.Index,
		AttachMode:     mode,
		AttachedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if previousMetadata.ObjectChecksum != "" && previousMetadata.ObjectChecksum != objectChecksum {
		metadata.PreviousProgramChecksum = previousMetadata.ObjectChecksum
	}
	if err := saveMetadata(cfg.MetadataPath(), metadata); err != nil {
		rt.Close(cfg.SafeDetachOnExit)
		return nil, err
	}

	return rt, nil
}

func (rt *Runtime) Close(detach bool) {
	if rt == nil {
		return
	}
	if rt.Link != nil && detach {
		_ = rt.Link.Unpin()
		_ = rt.Link.Close()
	}
	if rt.Collection != nil {
		rt.Collection.Close()
	}
}

func ensureRuntimeDirs(cfg Config) error {
	for _, dir := range []string{cfg.MapPinDir(), cfg.LinkPinDir(), cfg.ProgramPinDir(), cfg.MetadataDir(), filepath.Dir(cfg.SnapshotPath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func loadOrCreateSnapshot(path, objectChecksum string, logger *slog.Logger) (LastValidSnapshot, error) {
	snapshot, err := LoadLastValidSnapshot(path)
	if err == nil {
		return snapshot, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) && logger != nil {
		logger.Warn("ignoring invalid last-valid snapshot", "path", path, "error", RedactString(err.Error()))
	}

	snapshot = DefaultSnapshot(objectChecksum)
	if err := SaveLastValidSnapshot(path, snapshot); err != nil {
		return LastValidSnapshot{}, fmt.Errorf("save default last-valid snapshot: %w", err)
	}
	return snapshot, nil
}

func seedRuntimeConfig(runtimeConfig *ebpf.Map, cfg RuntimeConfigValue) error {
	if runtimeConfig == nil {
		return fmt.Errorf("runtime_config map not loaded")
	}
	key := uint32(0)
	if err := runtimeConfig.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("seed runtime_config: %w", err)
	}
	return nil
}

func attachOrUpdateLink(cfg Config, program *ebpf.Program, ifindex int, metrics *Metrics, logger *slog.Logger) (link.Link, string, error) {
	pinned, err := link.LoadPinnedLink(cfg.LinkPinPath(), nil)
	if err == nil {
		if err := pinned.Update(program); err != nil {
			return pinned, "", fmt.Errorf("update pinned XDP link: %w", err)
		}
		mode := cfg.XDPMode
		if mode == "" {
			mode = "native"
		}
		return pinned, mode, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) && logger != nil {
		logger.Warn("could not load pinned XDP link, attaching fresh link", "path", cfg.LinkPinPath(), "error", RedactString(err.Error()))
	}

	if cfg.XDPMode == "generic" {
		return attachFresh(cfg, program, ifindex, "generic", link.XDPGenericMode, metrics)
	}

	xdpLink, err := tryAttach(cfg, program, ifindex, link.XDPDriverMode)
	if err == nil {
		return xdpLink, "native", nil
	}
	if metrics != nil {
		metrics.IncAttachError("native")
	}
	if !cfg.AllowGenericFallback {
		return nil, "", fmt.Errorf("native XDP attach failed and generic fallback is disabled: %w", err)
	}
	if logger != nil {
		logger.Warn("native XDP attach failed, falling back to generic mode", "error", RedactString(err.Error()))
	}
	xdpLink, fallbackErr := tryAttach(cfg, program, ifindex, link.XDPGenericMode)
	if fallbackErr != nil {
		if metrics != nil {
			metrics.IncAttachError("generic")
		}
		return nil, "", fmt.Errorf("generic XDP fallback attach failed after native error %v: %w", err, fallbackErr)
	}
	return xdpLink, "generic", nil
}

func attachFresh(cfg Config, program *ebpf.Program, ifindex int, mode string, flags link.XDPAttachFlags, metrics *Metrics) (link.Link, string, error) {
	xdpLink, err := tryAttach(cfg, program, ifindex, flags)
	if err != nil {
		if metrics != nil {
			metrics.IncAttachError(mode)
		}
		return nil, "", err
	}
	return xdpLink, mode, nil
}

func tryAttach(cfg Config, program *ebpf.Program, ifindex int, flags link.XDPAttachFlags) (link.Link, error) {
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: ifindex,
		Flags:     flags,
	})
	if err != nil {
		return nil, err
	}
	if err := xdpLink.Pin(cfg.LinkPinPath()); err != nil {
		_ = xdpLink.Close()
		return nil, fmt.Errorf("pin XDP link: %w", err)
	}
	return xdpLink, nil
}

func saveMetadata(path string, metadata ProgramMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadMetadata(path string) (ProgramMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProgramMetadata{}, err
	}
	var metadata ProgramMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return ProgramMetadata{}, err
	}
	return metadata, nil
}

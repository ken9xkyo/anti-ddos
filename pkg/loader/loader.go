// Package loader handles compiling/loading the eBPF object and attaching XDP.
package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

//go:generate bash -c "which bpf2go >/dev/null 2>&1 || go install github.com/cilium/ebpf/cmd/bpf2go@v0.15.0"
//go:generate bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I../../bpf -mcpu=v3" bpf ../../bpf/xdp_antiddos.c -- -I../../bpf

const (
	// PinRoot is where all BPF maps and programs are pinned.
	PinRoot = "/sys/fs/bpf/antiddos"
	// ProgName in the ELF SEC("xdp") section.
	ProgName    = "xdp_antiddos"
	ProgPassthru = "xdp_passthru"
)

// Options configures the loader.
type Options struct {
	IngressIfaces []string // attach XDP on these
	EgressIface   string   // used as devmap[0]
	Mode          string   // "native" (default), "skb" (generic), "hw"
	PinPath       string
	Logger        *zap.Logger
}

// Loader owns the eBPF collection and attached links.
type Loader struct {
	opts  Options
	log   *zap.Logger
	coll  *ebpf.Collection
	links map[string]link.Link
}

// New creates a loader with sane defaults.
func New(opts Options) *Loader {
	if opts.PinPath == "" {
		opts.PinPath = PinRoot
	}
	if opts.Mode == "" {
		opts.Mode = "native"
	}
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	return &Loader{opts: opts, log: opts.Logger, links: map[string]link.Link{}}
}

// Load reads the compiled BPF object, pins maps, and returns the collection.
// objPath is the bpf2go-produced .o; when empty we look next to the binary.
func (l *Loader) Load(objPath string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit: %w", err)
	}
	if err := os.MkdirAll(l.opts.PinPath, 0o755); err != nil {
		return fmt.Errorf("mkdir pin: %w", err)
	}

	if objPath == "" {
		objPath = searchObject()
		if objPath == "" {
			return errors.New("BPF object not found; pass --bpf-obj or install to /usr/local/lib/antiddos/")
		}
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load spec %q: %w", objPath, err)
	}

	// Pin all maps by name so state survives daemon restarts.
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: l.opts.PinPath},
	})
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}
	l.coll = coll
	return nil
}

// searchObject returns the first existing BPF object from a short search list.
func searchObject() string {
	exe, _ := os.Executable()
	binDir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(binDir, "xdp_antiddos.o"),
		filepath.Join(binDir, "bpf_bpfel.o"),
		"/usr/local/lib/antiddos/xdp_antiddos.o",
		"/etc/antiddosd/xdp_antiddos.o",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// Collection returns the live collection (nil before Load).
func (l *Loader) Collection() *ebpf.Collection { return l.coll }

// Attach attaches the main program to every ingress interface.
func (l *Loader) Attach() error {
	if l.coll == nil {
		return errors.New("loader: not loaded")
	}
	prog := l.coll.Programs[ProgName]
	if prog == nil {
		return fmt.Errorf("program %q not found", ProgName)
	}

	flags := link.XDPDriverMode
	switch l.opts.Mode {
	case "skb":
		flags = link.XDPGenericMode
	case "hw":
		flags = link.XDPOffloadMode
	}

	for _, name := range l.opts.IngressIfaces {
		li, err := netlink.LinkByName(name)
		if err != nil {
			return fmt.Errorf("link %q: %w", name, err)
		}
		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: li.Attrs().Index,
			Flags:     flags,
		})
		if err != nil {
			return fmt.Errorf("attach xdp %q: %w", name, err)
		}
		// Pin the link so the program stays attached across restarts.
		pin := filepath.Join(l.opts.PinPath, "xdp_link_"+name)
		_ = lnk.Pin(pin)
		l.links[name] = lnk
		l.log.Info("xdp attached", zap.String("iface", name), zap.String("mode", l.opts.Mode))
	}
	return nil
}

// SetupDevmap writes the egress ifindex into egress_devmap[0].
func (l *Loader) SetupDevmap() error {
	if l.opts.EgressIface == "" {
		return nil
	}
	li, err := netlink.LinkByName(l.opts.EgressIface)
	if err != nil {
		return fmt.Errorf("egress iface: %w", err)
	}
	m := l.coll.Maps["egress_devmap"]
	if m == nil {
		return errors.New("egress_devmap not in collection")
	}
	idx := uint32(li.Attrs().Index)
	key := uint32(0)
	if err := m.Update(&key, &idx, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update devmap: %w", err)
	}
	l.log.Info("devmap configured",
		zap.String("egress", l.opts.EgressIface),
		zap.Uint32("ifindex", idx))
	return nil
}

// Close detaches programs and closes the collection.
func (l *Loader) Close() error {
	var errs []error
	for name, lnk := range l.links {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link %s: %w", name, err))
		}
	}
	if l.coll != nil {
		l.coll.Close()
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestValidateCollectionSpecAgainstPhase1Object(t *testing.T) {
	path := filepath.Join("..", "..", "build", "bpf", "xdp_data_plane.bpf.o")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Skip("phase1 BPF object is not built")
	}

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("LoadCollectionSpec() error = %v", err)
	}
	if err := ValidateCollectionSpec(spec); err != nil {
		t.Fatalf("ValidateCollectionSpec() error = %v", err)
	}
	EnableMapPinning(spec)
	for name := range ExpectedMaps {
		if spec.Maps[name].Pinning != ebpf.PinByName {
			t.Fatalf("%s was not marked for pinning", name)
		}
	}
}

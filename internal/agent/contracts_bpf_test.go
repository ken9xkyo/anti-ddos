package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

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

func TestContractLayoutsForAdditiveMaps(t *testing.T) {
	if got := unsafe.Sizeof(ServiceLPMV4Key{}); got != 12 {
		t.Fatalf("ServiceLPMV4Key size = %d, want 12", got)
	}
	if got := unsafe.Sizeof(RateKey{}); got != 16 {
		t.Fatalf("RateKey size = %d, want 16", got)
	}
	if got := unsafe.Sizeof(RateValueV2{}); got != 88 {
		t.Fatalf("RateValueV2 size = %d, want 88", got)
	}
	if got := unsafe.Offsetof(RateValueV2{}.Lock); got != 0 {
		t.Fatalf("RateValueV2.Lock offset = %d, want 0", got)
	}
	if got := unsafe.Offsetof(RateValueV2{}.LastRefillNS); got != 8 {
		t.Fatalf("RateValueV2.LastRefillNS offset = %d, want 8", got)
	}
}

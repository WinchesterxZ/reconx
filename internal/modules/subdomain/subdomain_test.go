package subdomain

import (
	"testing"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/scope"
	"github.com/reconx/reconx/internal/store"
	"github.com/reconx/reconx/pkg/logger"
)

func TestCleanLines(t *testing.T) {
	in := []string{
		"*.example.com",
		"SUB.EXAMPLE.COM",
		"   test.example.com   ",
		"invalid domain with spaces.com",
		"http://example.com",
		"valid-sub.example.com",
	}
	out := cleanLines(in)
	expected := []string{
		"example.com",
		"sub.example.com",
		"test.example.com",
		"valid-sub.example.com",
	}

	if len(out) != len(expected) {
		t.Fatalf("expected %d clean lines, got %d: %v", len(expected), len(out), out)
	}
	for i, exp := range expected {
		if out[i] != exp {
			t.Errorf("at index %d: expected %q, got %q", i, exp, out[i])
		}
	}
}

func TestSubdomainModuleCreation(t *testing.T) {
	cfg := config.DefaultConfig()
	log := logger.New(false, "")
	st := store.New("test-subdomain")
	sc := scope.New(cfg)
	m := New(cfg, st, sc, log, t.TempDir())
	if m == nil {
		t.Fatal("expected non-nil Module")
	}
}

package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistenceRenameAndDelete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "home.ovpn")
	mustWrite(t, source, "client\nremote vpn.example 1194\n")
	store := NewStore(root)
	p, err := store.Import(source)
	if err != nil {
		t.Fatal(err)
	}

	reloaded := NewStore(root)
	profiles, err := reloaded.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].ID != p.ID {
		t.Fatalf("List() = %#v", profiles)
	}
	renamed, err := reloaded.Rename(p.ID, "Work VPN")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "Work VPN" {
		t.Fatalf("Rename() name = %q", renamed.Name)
	}
	got, err := NewStore(root).Get(p.ID)
	if err != nil || got.Name != "Work VPN" {
		t.Fatalf("persisted profile = %#v, %v", got, err)
	}
	if err := reloaded.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.Dir); !os.IsNotExist(err) {
		t.Fatalf("profile dir still exists: %v", err)
	}
}

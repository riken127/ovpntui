package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateForExecutionRejectsTamperedProfile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := Profile{ID: "0123456789abcdef01234567", Name: "Tampered", Dir: dir}
	mustWrite(t, p.ConfigPath(), "client\nplugin /tmp/evil.so\n")
	err := ValidateForExecution(p)
	if err == nil || !strings.Contains(err.Error(), "plugin") {
		t.Fatalf("ValidateForExecution() error = %v", err)
	}
}

func TestValidateForExecutionRejectsAssetSymlinkEscape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.pem")
	mustWrite(t, outside, "CA")
	if err := os.Symlink(outside, filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	p := Profile{ID: "0123456789abcdef01234567", Name: "Tampered", Dir: dir}
	mustWrite(t, p.ConfigPath(), "client\nca ca.pem\n")
	err := ValidateForExecution(p)
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("ValidateForExecution() error = %v", err)
	}
}

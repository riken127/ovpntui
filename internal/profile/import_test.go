package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportCopiesAndNormalizesReferencedFiles(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	root := t.TempDir()
	mustWrite(t, filepath.Join(source, "ca cert.pem"), "CA")
	mustWrite(t, filepath.Join(source, "client.key"), "KEY")
	config := "client\nca \"ca cert.pem\"\nkey client.key\ntls-auth client.key 1\nauth-user-pass old-passwords.txt\n<cert>\nINLINE\n</cert>\n"
	configPath := filepath.Join(source, "office.ovpn")
	mustWrite(t, configPath, config)

	p, err := NewStore(root).Import(configPath)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if !p.NeedsAuth {
		t.Fatal("NeedsAuth = false, want true")
	}
	data, err := os.ReadFile(p.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	normalized := string(data)
	for _, want := range []string{"ca asset-01.pem", "key asset-02.key", "tls-auth asset-02.key 1", "auth-user-pass", "<cert>"} {
		if !strings.Contains(normalized, want) {
			t.Errorf("normalized config does not contain %q:\n%s", want, normalized)
		}
	}
	if strings.Contains(normalized, "old-passwords") {
		t.Fatal("import retained an auth-user-pass filename")
	}
	for _, name := range []string{"asset-01.pem", "asset-02.key", ConfigFilename, MetadataFilename} {
		info, statErr := os.Stat(filepath.Join(p.Dir, name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
}

func TestImportRemovesInlineCredentials(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	path := filepath.Join(source, "inline.ovpn")
	mustWrite(t, path, "client\n<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\nremote vpn.example 1194\n")
	p, err := NewStore(t.TempDir()).Import(path)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.ConfigPath())
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "alice") {
		t.Fatalf("inline credentials leaked:\n%s", data)
	}
	if !strings.Contains(string(data), "auth-user-pass\n") {
		t.Fatalf("auth directive missing:\n%s", data)
	}
}

func TestImportFailsForMissingReferenceWithoutPartialProfile(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	root := t.TempDir()
	path := filepath.Join(source, "broken.ovpn")
	mustWrite(t, path, "client\ncert missing.crt\n")
	_, err := NewStore(root).Import(path)
	if err == nil || !strings.Contains(err.Error(), "missing.crt") {
		t.Fatalf("Import() error = %v", err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("partial profiles left behind: %v", entries)
	}
}

func TestImportNormalizesReferencesInsideConnectionBlock(t *testing.T) {
	t.Parallel()
	source := t.TempDir()
	mustWrite(t, filepath.Join(source, "ca.pem"), "CA")
	path := filepath.Join(source, "connection.ovpn")
	mustWrite(t, path, "client\n<connection>\nremote vpn.example\nca ca.pem\n</connection>\n")
	p, err := NewStore(t.TempDir()).Import(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ca asset-01.pem") {
		t.Fatalf("connection reference was not normalized:\n%s", data)
	}
}

func TestImportRejectsCommandsInElevatedProfile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "unsafe.ovpn")
	mustWrite(t, path, "client\nscript-security 2\nup /tmp/payload\n")
	_, err := NewStore(t.TempDir()).Import(path)
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("Import() error = %v", err)
	}
}

func TestImportRejectsUnsupportedInlineCredentialBlock(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "proxy-auth.ovpn")
	mustWrite(t, path, "client\n<http-proxy-user-pass>\nalice\nsecret\n</http-proxy-user-pass>\n")
	_, err := NewStore(t.TempDir()).Import(path)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("Import() error = %v", err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

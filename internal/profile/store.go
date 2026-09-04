package profile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store persists imported profiles below one private directory.
type Store struct {
	root string
	mu   sync.Mutex
}

func NewStore(root string) *Store { return &Store{root: root} }

func (s *Store) List() ([]Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	profiles := make([]Profile, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profileDir := filepath.Join(s.root, entry.Name())
		p, readErr := readMetadata(profileDir)
		if readErr != nil {
			continue
		}
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return strings.ToLower(profiles[i].Name) < strings.ToLower(profiles[j].Name)
	})
	return profiles, nil
}

func (s *Store) Get(id string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validID(id) {
		return Profile{}, errors.New("invalid profile id")
	}
	return readMetadata(filepath.Join(s.root, id))
}

func (s *Store) Rename(id, name string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" {
		return Profile{}, errors.New("profile name cannot be empty")
	}
	if !validID(id) {
		return Profile{}, errors.New("invalid profile id")
	}
	p, err := readMetadata(filepath.Join(s.root, id))
	if err != nil {
		return Profile{}, err
	}
	p.Name = name
	if err := writeMetadata(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validID(id) {
		return errors.New("invalid profile id")
	}
	dir := filepath.Join(s.root, id)
	if _, err := os.Stat(filepath.Join(dir, MetadataFilename)); err != nil {
		return fmt.Errorf("profile not found: %w", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("delete profile: %w", err)
	}
	return nil
}

func newProfile(name, dir string, needsAuth bool) (Profile, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Profile{}, fmt.Errorf("generate profile id: %w", err)
	}
	return Profile{ID: hex.EncodeToString(raw[:]), Name: name, CreatedAt: time.Now().UTC(), NeedsAuth: needsAuth, Dir: dir}, nil
}

func readMetadata(dir string) (Profile, error) {
	data, err := os.ReadFile(filepath.Join(dir, MetadataFilename))
	if err != nil {
		return Profile{}, fmt.Errorf("read profile metadata: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return Profile{}, fmt.Errorf("decode profile metadata: %w", err)
	}
	if !validID(p.ID) || strings.TrimSpace(p.Name) == "" {
		return Profile{}, errors.New("invalid profile metadata")
	}
	p.Dir = dir
	return p, nil
}

func writeMetadata(p Profile) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode profile metadata: %w", err)
	}
	return atomicWrite(filepath.Join(p.Dir, MetadataFilename), append(data, '\n'), 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func validID(id string) bool {
	if len(id) != 24 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

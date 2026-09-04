package profile

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateForExecution checks the private copy again immediately before it is
// passed to an elevated OpenVPN process. This also protects profiles imported
// by older application versions.
func ValidateForExecution(p Profile) error {
	configPath := p.ConfigPath()
	info, err := os.Lstat(configPath)
	if err != nil {
		return fmt.Errorf("open imported configuration: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("imported configuration is not a regular file")
	}
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("open imported configuration: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	inlineTag := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		if inlineTag != "" {
			if lower == "</"+inlineTag+">" {
				inlineTag = ""
			}
			continue
		}
		if lower == "<connection>" || lower == "</connection>" {
			continue
		}
		if strings.HasPrefix(lower, "<") && strings.HasSuffix(lower, ">") && !strings.HasPrefix(lower, "</") {
			inlineTag = strings.TrimSuffix(strings.TrimPrefix(lower, "<"), ">")
			if !fileDirectives[inlineTag] {
				return fmt.Errorf("inline block <%s> is not supported in elevated profiles", inlineTag)
			}
			continue
		}
		fields, parseErr := splitOption(line)
		if parseErr != nil {
			return fmt.Errorf("parse imported configuration: %w", parseErr)
		}
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(strings.TrimPrefix(fields[0], "--"))
		if unsafeDirectives[directive] {
			return fmt.Errorf("directive %q is not allowed in elevated profiles", directive)
		}
		if directive == "auth-user-pass" && len(fields) > 1 {
			return errors.New("auth-user-pass may not reference a persistent credential file")
		}
		if !fileDirectives[directive] || len(fields) < 2 || fields[1] == "[inline]" {
			continue
		}
		if err := validatePrivateAsset(p.Dir, fields[1]); err != nil {
			return fmt.Errorf("%s references %q: %w", directive, fields[1], err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read imported configuration: %w", err)
	}
	if inlineTag != "" {
		return fmt.Errorf("unterminated <%s> block", inlineTag)
	}
	return nil
}

func validatePrivateAsset(profileDir, name string) error {
	if filepath.IsAbs(name) {
		return errors.New("absolute asset paths are not allowed after import")
	}
	target := filepath.Join(profileDir, name)
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(profileDir, resolved)
	if err != nil {
		return err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("asset escapes the private profile directory")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("asset is not a regular file")
	}
	return nil
}

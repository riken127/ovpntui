package profile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var fileDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true, "pkcs12": true, "dh": true,
	"tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"crl-verify": true, "extra-certs": true, "secret": true,
}

var unsafeDirectives = map[string]bool{
	"askpass": true, "auth-user-pass-verify": true, "client-connect": true, "client-crresponse": true,
	"client-disconnect": true, "config": true, "daemon": true, "down": true,
	"http-proxy-user-pass": true,
	"ipchange":             true, "learn-address": true, "log": true, "log-append": true,
	"management": true, "plugin": true, "route-pre-down": true, "route-up": true,
	"script-security": true, "status": true, "syslog": true, "tls-verify": true,
	"tmp-dir": true, "up": true, "writepid": true,
}

// Import copies and normalizes an OpenVPN configuration and its local dependencies.
func (s *Store) Import(source string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	abs, err := filepath.Abs(source)
	if err != nil {
		return Profile{}, fmt.Errorf("resolve profile path: %w", err)
	}
	if !strings.EqualFold(filepath.Ext(abs), ".ovpn") {
		return Profile{}, errors.New("profile must have an .ovpn extension")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Profile{}, fmt.Errorf("open profile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Profile{}, errors.New("profile path is not a regular file")
	}
	p, err := newProfile(strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs)), "", false)
	if err != nil {
		return Profile{}, err
	}
	p.Dir = filepath.Join(s.root, p.ID)
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return Profile{}, fmt.Errorf("create profile directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(p.Dir)
		}
	}()

	in, err := os.Open(abs)
	if err != nil {
		return Profile{}, err
	}
	defer func() { _ = in.Close() }()
	normalized, needsAuth, err := normalize(in, filepath.Dir(abs), p.Dir)
	if err != nil {
		return Profile{}, err
	}
	p.NeedsAuth = needsAuth
	if err := atomicWrite(filepath.Join(p.Dir, ConfigFilename), normalized, 0o600); err != nil {
		return Profile{}, fmt.Errorf("write imported profile: %w", err)
	}
	if err := writeMetadata(p); err != nil {
		return Profile{}, err
	}
	committed = true
	return p, nil
}

func normalize(r io.Reader, sourceDir, destinationDir string) ([]byte, bool, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var output strings.Builder
	needsAuth := false
	inlineAuth := false
	inlineTag := ""
	copied := make(map[string]string)
	counter := 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if inlineAuth {
			if lower == "</auth-user-pass>" {
				inlineAuth = false
			}
			continue
		}
		if inlineTag != "" {
			output.WriteString(line + "\n")
			if lower == "</"+inlineTag+">" {
				inlineTag = ""
			}
			continue
		}
		if lower == "<auth-user-pass>" {
			needsAuth = true
			inlineAuth = true
			output.WriteString("auth-user-pass\n")
			continue
		}
		if lower == "<connection>" || lower == "</connection>" {
			output.WriteString(line + "\n")
			continue
		}
		if strings.HasPrefix(lower, "<") && strings.HasSuffix(lower, ">") && !strings.HasPrefix(lower, "</") {
			inlineTag = strings.TrimSuffix(strings.TrimPrefix(lower, "<"), ">")
			if !fileDirectives[inlineTag] {
				return nil, false, fmt.Errorf("inline block <%s> is not supported in elevated profiles", inlineTag)
			}
			output.WriteString(line + "\n")
			continue
		}
		fields, parseErr := splitOption(trimmed)
		if parseErr != nil {
			return nil, false, fmt.Errorf("parse configuration line %q: %w", line, parseErr)
		}
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") || strings.HasPrefix(fields[0], "<") {
			output.WriteString(line + "\n")
			continue
		}
		directive := strings.ToLower(strings.TrimPrefix(fields[0], "--"))
		if unsafeDirectives[directive] {
			return nil, false, fmt.Errorf("directive %q is not allowed in elevated profiles", directive)
		}
		if directive == "auth-user-pass" {
			needsAuth = true
			output.WriteString("auth-user-pass\n")
			continue
		}
		if !fileDirectives[directive] || len(fields) < 2 || fields[1] == "[inline]" {
			output.WriteString(line + "\n")
			continue
		}
		source := fields[1]
		if !filepath.IsAbs(source) {
			source = filepath.Join(sourceDir, source)
		}
		source = filepath.Clean(source)
		name, ok := copied[source]
		if !ok {
			counter++
			ext := filepath.Ext(source)
			name = fmt.Sprintf("asset-%02d%s", counter, ext)
			if err := copyPrivateFile(source, filepath.Join(destinationDir, name)); err != nil {
				return nil, false, fmt.Errorf("%s references %q: %w", directive, fields[1], err)
			}
			copied[source] = name
		}
		fields[1] = name
		output.WriteString(joinOption(fields) + "\n")
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("read profile: %w", err)
	}
	if inlineAuth {
		return nil, false, errors.New("unterminated <auth-user-pass> block")
	}
	if inlineTag != "" {
		return nil, false, fmt.Errorf("unterminated <%s> block", inlineTag)
	}
	return []byte(output.String()), needsAuth, nil
}

func splitOption(line string) ([]string, error) {
	var fields []string
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) || line[i] == '#' || line[i] == ';' {
			break
		}
		var b strings.Builder
		quote := byte(0)
		if line[i] == '\'' || line[i] == '"' {
			quote = line[i]
			i++
		}
		for i < len(line) {
			if quote != 0 {
				if line[i] == quote {
					i++
					break
				}
			} else if line[i] == ' ' || line[i] == '\t' {
				break
			}
			if line[i] == '\\' && i+1 < len(line) {
				i++
				b.WriteByte(line[i])
				i++
				continue
			}
			b.WriteByte(line[i])
			i++
		}
		if quote != 0 && (i == len(line) && (len(line) == 0 || line[i-1] != quote)) {
			return nil, errors.New("unterminated quote")
		}
		fields = append(fields, b.String())
	}
	return fields, nil
}

func joinOption(fields []string) string {
	quoted := make([]string, len(fields))
	for i, field := range fields {
		if strings.ContainsAny(field, " \t#;\"") {
			quoted[i] = strconv.Quote(field)
		} else {
			quoted[i] = field
		}
	}
	return strings.Join(quoted, " ")
}

func copyPrivateFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

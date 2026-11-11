package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// CookieStore holds flat key=value cookies without domain, path, or expiration metadata.
type CookieStore struct {
	keys   []string
	values map[string]string
}

func NewCookieStore() *CookieStore {
	return &CookieStore{
		values: make(map[string]string),
	}
}

func (cs *CookieStore) Set(name, value string) {
	if name == "" {
		return
	}
	if _, exists := cs.values[name]; !exists {
		cs.keys = append(cs.keys, name)
	}
	cs.values[name] = value
}

func (cs *CookieStore) Delete(name string) {
	if _, exists := cs.values[name]; !exists {
		return
	}
	delete(cs.values, name)
	for i, k := range cs.keys {
		if k == name {
			cs.keys = append(cs.keys[:i], cs.keys[i+1:]...)
			break
		}
	}
}

func (cs *CookieStore) Count() int {
	return len(cs.keys)
}

func (cs *CookieStore) HeaderValue() string {
	if len(cs.keys) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cs.keys))
	for _, k := range cs.keys {
		parts = append(parts, k+"="+cs.values[k])
	}
	return strings.Join(parts, "; ")
}

func (cs *CookieStore) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "Warning: cookie file %q not found, proceeding with empty cookies\n", path)
			return nil
		}
		return fmt.Errorf("open cookie file %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			continue
		}
		cs.Set(key, val)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read cookie file %q: %w", path, err)
	}
	return nil
}

func (cs *CookieStore) SaveToFile(path string) error {
	var b strings.Builder
	for _, k := range cs.keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cs.values[k])
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write cookie file %q: %w", path, err)
	}
	return nil
}

// UpdateFromResponse applies Set-Cookie headers from an HTTP response.
// Expired or Max-Age<=0 cookies are removed rather than stored as "deleted".
func (cs *CookieStore) UpdateFromResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	now := time.Now()
	for _, c := range resp.Cookies() {
		if c.Name == "" {
			continue
		}
		// In Go net/http, Max-Age<=0 in Set-Cookie yields c.MaxAge < 0.
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(now)) {
			cs.Delete(c.Name)
			continue
		}
		cs.Set(c.Name, c.Value)
	}
}

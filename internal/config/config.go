// Package config loads optional JSON settings files for the server and
// client binaries. A config file is entirely optional — every field in
// it just seeds that flag's default, so an explicit CLI flag always
// wins, and a missing config file falls back to today's pure-flags
// behavior unchanged.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads path as JSON into v. A missing file is reported via found
// == false, not an error — the caller treats that as "no config, use
// flag defaults" rather than failing to start.
func Load(path string, v any) (found bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("parse config %s: %w", path, err)
	}
	return true, nil
}

// FindFlag manually scans args for -name/--name (space- or
// =-separated) and returns its value. Used only to read -config itself
// before the real flag.FlagSet exists to seed other flags' defaults —
// flag.Parse can't do this because all flags must be defined up front,
// and a throwaway FlagSet would abort on the first *other* flag it
// doesn't recognize.
func FindFlag(args []string, name string) string {
	long := "--" + name
	short := "-" + name
	for i, a := range args {
		if a == short || a == long {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if v, ok := cutPrefix(a, short+"="); ok {
			return v
		}
		if v, ok := cutPrefix(a, long+"="); ok {
			return v
		}
	}
	return ""
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

// Str returns cfgVal if non-empty, else fallback — for seeding a flag's
// default from an optional config field.
func Str(cfgVal, fallback string) string {
	if cfgVal != "" {
		return cfgVal
	}
	return fallback
}

// Int returns cfgVal if non-zero, else fallback.
func Int(cfgVal, fallback int) int {
	if cfgVal != 0 {
		return cfgVal
	}
	return fallback
}

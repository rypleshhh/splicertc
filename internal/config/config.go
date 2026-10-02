// Package config loads the JSON config files. Values from the file are
// used as flag defaults, so command line flags still override them.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads a JSON file into v. Missing file is not an error, found is false.
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

// FindFlag gets the value of -name from args by hand. We need -config
// before flag.Parse because the config sets the other flags' defaults.
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

// Str returns cfgVal, or fallback if it's empty.
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

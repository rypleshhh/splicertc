package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	type cfg struct {
		Addr string `json:"addr"`
	}
	tests := []struct {
		name      string
		content   string // "" = no file
		wantFound bool
		wantErr   string
		wantAddr  string
	}{
		{"no file", "", false, "", ""},
		{"valid", `{"addr": ":443"}`, true, "", ":443"},
		{"typo in a field name", `{"adr": ":443"}`, false, "unknown field", ""},
		{"broken json", `{"addr":`, false, "parse config", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.json")
			if tt.content != "" {
				if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var c cfg
			found, err := Load(path, &c)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || found != tt.wantFound || c.Addr != tt.wantAddr {
				t.Fatalf("got found=%v addr=%q err=%v", found, c.Addr, err)
			}
		})
	}
}

func TestFindFlag(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-config", "a.json"}, "a.json"},
		{[]string{"--config=b.json"}, "b.json"},
		{[]string{"-mode", "vpn", "-config=c.json"}, "c.json"},
		{[]string{"--", "-config", "x.json"}, ""},
		{[]string{"-config"}, ""},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			if got := FindFlag(tt.args, "config"); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

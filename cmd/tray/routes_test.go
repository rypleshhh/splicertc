package main

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestServerIPFromLine(t *testing.T) {
	cases := []struct {
		line    string
		want    string // "" = error
		wantErr bool
	}{
		{line: "2026/10/22 12:00:00 connected to vpn channel 203.0.113.5:587", want: "203.0.113.5"},
		{line: "connected to vpn channel 203.0.113.5:587 (reconnect)", want: "203.0.113.5"},
		{line: "connected to vpn channel [::ffff:203.0.113.5]:587", want: "203.0.113.5"},
		{line: "connected to vpn channel example.com:587", wantErr: true},
		{line: "connected to vpn channel [2001:db8::1]:587", wantErr: true},
		{line: "connected to vpn channel 203.0.113.5", wantErr: true},
		{line: "connected to vpn channel", wantErr: true},
		{line: "connected to vpn channel 1.2.3.4';calc;'#:587", wantErr: true},
		{line: "connected to glue channel 1.2.3.4:993", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			ip, err := serverIPFromLine(c.line)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %s", ip)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ip.String() != c.want {
				t.Errorf("got %s, want %s", ip, c.want)
			}
		})
	}
}

func TestTunConfigFromJSON(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		want    tunConfig
		wantErr bool
	}{
		{name: "defaults", json: `{"mode":"vpn"}`,
			want: tunConfig{Name: "dormvpn0", IP: netip.MustParseAddr("10.66.0.2"), Gateway: netip.MustParseAddr("10.66.0.1"), PrefixLen: 24}},
		{name: "custom", json: `{"vpn_tun_name":"mytun","vpn_subnet":"10.70.8.0/22"}`,
			want: tunConfig{Name: "mytun", IP: netip.MustParseAddr("10.70.8.2"), Gateway: netip.MustParseAddr("10.70.8.1"), PrefixLen: 22}},
		{name: "host bits are masked", json: `{"vpn_subnet":"192.168.5.77/24"}`,
			want: tunConfig{Name: "dormvpn0", IP: netip.MustParseAddr("192.168.5.2"), Gateway: netip.MustParseAddr("192.168.5.1"), PrefixLen: 24}},
		{name: "too small", json: `{"vpn_subnet":"10.0.0.0/31"}`, wantErr: true},
		{name: "ipv6", json: `{"vpn_subnet":"fd00::/64"}`, wantErr: true},
		{name: "garbage", json: `{"vpn_subnet":"nope"}`, wantErr: true},
		{name: "broken json", json: `{`, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := tunConfigFromJSON([]byte(c.json))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestPSQuote(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"10.66.0.2", true},
		{"dormvpn0", true},
		{"My TUN-1", true},
		{"", false},
		{"a'b", false},
		{"a\u2019b", false}, // PowerShell takes curly quotes as quotes too
		{"$(calc)", false},
		{"a`b", false},
		{"a;b", false},
		{strings.Repeat("a", 65), false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			q, err := psQuote(c.in)
			if (err == nil) != c.ok {
				t.Fatalf("psQuote(%q) = %q, %v; want ok=%v", c.in, q, err, c.ok)
			}
			if c.ok && q != "'"+c.in+"'" {
				t.Errorf("got %q", q)
			}
		})
	}
}

func TestSetupArgsRejectsUnsafeTunName(t *testing.T) {
	tc := tunConfig{Name: "x'; Remove-Item C:\\ -Recurse; '", IP: netip.MustParseAddr("10.66.0.2"),
		Gateway: netip.MustParseAddr("10.66.0.1"), PrefixLen: 24}
	if _, err := setupArgs(netip.MustParseAddr("203.0.113.5"), tc); err == nil {
		t.Fatal("expected an error for a tun name with quotes")
	}
}

func decodeEncodedCommand(t *testing.T, enc string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%2 != 0 {
		t.Fatal("odd UTF-16 length")
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// typicalArgs is what connect() passes with the default config.
func typicalArgs(t *testing.T) []string {
	t.Helper()
	tc, err := tunConfigFromJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	args, err := setupArgs(netip.MustParseAddr("203.0.113.5"), tc)
	if err != nil {
		t.Fatal(err)
	}
	return args
}

func TestEncodedCommandRoundTrip(t *testing.T) {
	args := typicalArgs(t)
	got := decodeEncodedCommand(t, encodedCommand(routeScript, args))
	want := "$ProgressPreference = 'SilentlyContinue'\n& {\n" + routeScript +
		"\n} -ServerIP '203.0.113.5' -TunName 'dormvpn0' -TunIP '10.66.0.2' -TunGateway '10.66.0.1' -TunPrefixLength 24 *>&1"
	if got != want {
		t.Errorf("decoded command differs, tail: %q", got[max(0, len(got)-120):])
	}
}

// CreateProcess takes at most 32767 UTF-16 units of command line, the
// whole script travels in it.
func TestRouteScriptCommandLineFits(t *testing.T) {
	const maxCommandLine = 32767
	exe := systemExe(`WindowsPowerShell\v1.0\powershell.exe`)
	n := len(exe) + 3 // quotes and a space
	for _, a := range powershellArgs(typicalArgs(t)) {
		n += len(a) + 1
	}
	t.Logf("command line: %d characters (script %d bytes)", n, len(routeScript))
	if n > maxCommandLine*3/4 {
		t.Errorf("command line is %d characters, too close to the %d limit", n, maxCommandLine)
	}
}

func TestIsUnderDir(t *testing.T) {
	cases := []struct {
		path, root string
		want       bool
	}{
		{`C:\Program Files\splicertc`, `C:\Program Files`, true},
		{`c:\program files\splicertc`, `C:\Program Files`, true},
		{`C:\Program Files`, `C:\Program Files\`, true},
		{`C:\Program Files Evil\x`, `C:\Program Files`, false},
		{`C:\Users\me\Downloads`, `C:\Program Files`, false},
		{`C:\Program Files\..\Users\me`, `C:\Program Files`, false},
		{`C:\x`, ``, false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := isUnderDir(c.path, c.root); got != c.want {
				t.Errorf("isUnderDir(%q, %q) = %v, want %v", c.path, c.root, got, c.want)
			}
		})
	}
}

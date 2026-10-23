package main

import (
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
)

// fakeIptables keeps rules per "table/chain" in order and answers the
// commands firewall sends, so the rule logic can be tested without root
// and without Linux.
type fakeIptables struct {
	chains map[string][]string
	// a rule whose spec contains this string can't be added
	failOn string
}

func newFakeIptables(dockerUser bool) *fakeIptables {
	f := &fakeIptables{chains: map[string][]string{
		"filter/INPUT": nil, "filter/FORWARD": nil, "nat/POSTROUTING": nil, "mangle/FORWARD": nil,
	}}
	if dockerUser {
		f.chains["filter/DOCKER-USER"] = nil
	}
	return f
}

// install replaces runCmd with f for the duration of the test.
func (f *fakeIptables) install(t *testing.T) {
	old := runCmd
	runCmd = f.run
	t.Cleanup(func() { runCmd = old })
}

func (f *fakeIptables) run(name string, args ...string) (string, error) {
	if len(args) >= 2 && args[0] == "-w" {
		args = args[2:]
	}
	table := "filter"
	if len(args) >= 2 && args[0] == "-t" {
		table, args = args[1], args[2:]
	}
	op, key := args[0], table+"/"+args[1]
	rules, exists := f.chains[key]
	if !exists {
		return "", errors.New("no chain/target/match by that name")
	}
	spec := strings.Join(args[2:], " ")
	switch op {
	case "-S":
		return "", nil
	case "-C":
		if !slices.Contains(rules, spec) {
			return "", errors.New("bad rule (does a matching rule exist in that chain?)")
		}
	case "-A", "-I":
		if f.failOn != "" && strings.Contains(spec, f.failOn) {
			return "", errors.New("add failed")
		}
		if op == "-I" {
			spec = strings.Join(args[3:], " ") // skip the position
			f.chains[key] = append([]string{spec}, rules...)
		} else {
			f.chains[key] = append(rules, spec)
		}
	case "-D":
		i := slices.Index(rules, spec)
		if i < 0 {
			return "", errors.New("bad rule (does a matching rule exist in that chain?)")
		}
		f.chains[key] = slices.Delete(rules, i, i+1)
	}
	return "", nil
}

func (f *fakeIptables) total() int {
	n := 0
	for _, r := range f.chains {
		n += len(r)
	}
	return n
}

func testFirewall(allowPrivate bool, publicIPs ...net.IP) *firewall {
	return newVPNFirewall("iptables", "10.66.0.0/24", "eth0", "dormvpn0", allowPrivate, publicIPs)
}

// The DROPs must come before the ACCEPTs in FORWARD and DOCKER-USER,
// towards the client only established connections get through.
func TestFirewallRuleOrder(t *testing.T) {
	ipt := newFakeIptables(true)
	ipt.install(t)
	if err := testFirewall(false, net.ParseIP("203.0.113.5")).apply(); err != nil {
		t.Fatal(err)
	}

	order := []string{
		"-i dormvpn0 -d 169.254.0.0/16 -j DROP",
		"-i dormvpn0 -d 10.0.0.0/8 -j DROP",
		"-i dormvpn0 -d 203.0.113.5 -j DROP",
		"-i dormvpn0 -p tcp --dport 25 -j DROP",
		"-o dormvpn0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-o dormvpn0 -j DROP",
		"-i dormvpn0 -j ACCEPT",
	}
	for _, chain := range []string{"filter/FORWARD", "filter/DOCKER-USER"} {
		rules := ipt.chains[chain]
		last := -1
		for _, want := range order {
			i := slices.Index(rules, want)
			if i < 0 {
				t.Fatalf("%s: missing %q in %q", chain, want, rules)
			}
			if i < last {
				t.Fatalf("%s: %q is in the wrong place: %q", chain, want, rules)
			}
			last = i
		}
		if slices.Contains(rules, "-o dormvpn0 -j ACCEPT") {
			t.Fatalf("%s: everything towards the client is accepted", chain)
		}
	}
	if ipt.chains["filter/INPUT"][0] != "-i dormvpn0 -j DROP" {
		t.Fatalf("INPUT: %q", ipt.chains["filter/INPUT"])
	}
	if len(ipt.chains["nat/POSTROUTING"]) != 1 || len(ipt.chains["mangle/FORWARD"]) != 1 {
		t.Fatalf("nat %q, mangle %q", ipt.chains["nat/POSTROUTING"], ipt.chains["mangle/FORWARD"])
	}

	// a restart finds everything in place and adds nothing twice
	before := ipt.total()
	if err := testFirewall(false, net.ParseIP("203.0.113.5")).apply(); err != nil {
		t.Fatal(err)
	}
	if ipt.total() != before {
		t.Fatalf("second apply changed the rule count %d -> %d", before, ipt.total())
	}
}

// Without docker there is no DOCKER-USER chain, that's not an error.
func TestFirewallWithoutDockerUser(t *testing.T) {
	ipt := newFakeIptables(false)
	ipt.install(t)
	if err := testFirewall(false).apply(); err != nil {
		t.Fatal(err)
	}
	if len(ipt.chains["filter/FORWARD"]) == 0 {
		t.Fatal("no FORWARD rules")
	}
	if _, ok := ipt.chains["filter/DOCKER-USER"]; ok {
		t.Fatal("DOCKER-USER was created")
	}
}

// Any protective rule that can't be added stops the setup, and what was
// added already is removed again. Only the MSS clamp is optional.
func TestFirewallFailClosed(t *testing.T) {
	tests := []struct {
		failOn  string
		wantErr bool
	}{
		{"MASQUERADE", true},
		{"169.254.0.0/16", true},
		{"172.16.0.0/12", true},
		{"--dport 25", true},
		{"conntrack", true},
		{"-o dormvpn0 -j DROP", true},
		{"TCPMSS", false},
	}
	for _, tt := range tests {
		t.Run(tt.failOn, func(t *testing.T) {
			ipt := newFakeIptables(true)
			ipt.failOn = tt.failOn
			ipt.install(t)
			err := testFirewall(false).apply()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && ipt.total() != 0 {
				t.Fatalf("rules left behind after a failed setup: %v", ipt.chains)
			}
		})
	}
}

// Rules of older versions that accepted everything towards the client
// are removed; with allow_private_destinations the private DROPs too.
func TestFirewallMigration(t *testing.T) {
	ipt := newFakeIptables(true)
	ipt.chains["filter/FORWARD"] = []string{"-o dormvpn0 -j ACCEPT", "-i dormvpn0 -d 10.0.0.0/8 -j DROP"}
	ipt.chains["filter/DOCKER-USER"] = []string{"-o dormvpn0 -j ACCEPT"}
	ipt.install(t)
	if err := testFirewall(true).apply(); err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"filter/FORWARD", "filter/DOCKER-USER"} {
		for _, old := range []string{"-o dormvpn0 -j ACCEPT", "-i dormvpn0 -d 10.0.0.0/8 -j DROP"} {
			if slices.Contains(ipt.chains[chain], old) {
				t.Fatalf("%s: old rule %q is still there", chain, old)
			}
		}
	}
}

// Shutdown removes every rule this server added, other rules stay.
func TestFirewallRemove(t *testing.T) {
	ipt := newFakeIptables(true)
	ipt.chains["filter/FORWARD"] = []string{"-i docker0 -j ACCEPT"}
	ipt.install(t)
	fw := testFirewall(false, net.ParseIP("203.0.113.5"))
	if err := fw.apply(); err != nil {
		t.Fatal(err)
	}
	fw.remove()
	if ipt.total() != 1 || ipt.chains["filter/FORWARD"][0] != "-i docker0 -j ACCEPT" {
		t.Fatalf("after remove: %v", ipt.chains)
	}
}

func TestDetectIptables(t *testing.T) {
	const fewRules = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\nCOMMIT\n"
	const manyRules = "*filter\n-A FORWARD -j DOCKER-USER\n-A DOCKER-USER -j RETURN\n-A INPUT -j ACCEPT\nCOMMIT\n"
	tests := []struct {
		name        string
		legacy, nft string // "" = command fails
		want        string
	}{
		{"legacy has more", manyRules, fewRules, "iptables-legacy"},
		{"nft has more", fewRules, manyRules, "iptables-nft"},
		{"equal", fewRules, fewRules, "iptables-nft"},
		{"only legacy works", fewRules, "", "iptables-legacy"},
		{"only nft works", "", fewRules, "iptables-nft"},
		{"nothing works", "", "", "iptables"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := runCmd
			defer func() { runCmd = old }()
			runCmd = func(name string, args ...string) (string, error) {
				out := map[string]string{"iptables-legacy-save": tt.legacy, "iptables-nft-save": tt.nft}[name]
				if out == "" {
					return "", errors.New("not found")
				}
				return out, nil
			}
			if got := detectIptables(); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

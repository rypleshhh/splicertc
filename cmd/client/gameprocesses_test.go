package main

import (
	"reflect"
	"testing"
)

func TestParseGameProcesses(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"deadlock.exe", []string{"deadlock.exe"}},
		{"Deadlock.exe, DOTA2.exe", []string{"deadlock.exe", "dota2.exe"}},
		{" cs2.exe ,, dota2.exe", []string{"cs2.exe", "dota2.exe"}},
	}
	for _, c := range cases {
		got := parseGameProcesses(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseGameProcesses(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

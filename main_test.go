package main

import (
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	for key, c := range configByHost {
		if key == "android.googlesource.com" {
			continue
		}
		if !strings.Contains(c.Endpoint.AuthURL, key) {
			t.Errorf("bad auth url for key %s: %s", key, c.Endpoint.AuthURL)
		}
		if !strings.Contains(c.Endpoint.TokenURL, key) {
			t.Errorf("bad token url for key %s: %s", key, c.Endpoint.TokenURL)
		}
		if c.Endpoint.DeviceAuthURL != "" && !strings.Contains(c.Endpoint.DeviceAuthURL, key) {
			t.Errorf("bad device auth url for key %s: %s", key, c.Endpoint.DeviceAuthURL)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("key=value")
	f.Add("key=")
	f.Add("==")
	f.Add("\n\n\n")
	f.Add("key=value=long")
	f.Add("wwwauth[]=value1\nwwwauth[]=value2")
	f.Fuzz(func(_ *testing.T, s string) {
		parse(s)
	})
}

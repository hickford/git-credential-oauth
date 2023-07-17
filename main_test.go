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
		if key == "dev.azure.com" {
			continue
		}
		if !strings.Contains(c.Endpoint.AuthURL, key) {
			t.Errorf("bad auth url for key %s: %s", key, c.Endpoint.AuthURL)
		}
		if !strings.Contains(c.Endpoint.TokenURL, key) {
			t.Errorf("bad token url for key %s: %s", key, c.Endpoint.TokenURL)
		}
	}
}

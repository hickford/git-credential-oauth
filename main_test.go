package main

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	for key, c := range configByHost {
		if key == "android.googlesource.com" || key == "gist.github.com" {
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

func TestQR(t *testing.T) {
	msg := os.Getenv("QR_MSG")
	if msg == "" {
		t.Skip("no QR_MSG set, skipping")
	}
	if err := writeQRCode(os.Stdout, msg); err != nil {
		t.Fatal(err)
	}
}

func TestEvalConfigValuePlain(t *testing.T) {
	tests := map[string]string{
		"":                "",
		"   ":             "",
		"plain":           "plain",
		"  padded  ":      "padded",
		"has `backtick` in middle":     "has `backtick` in middle",
		"`only-open":                   "`only-open",
		"only-close`":                  "only-close`",
		"`":                            "`",
	}
	for input, want := range tests {
		got, err := evalConfigValue(input)
		if err != nil {
			t.Errorf("evalConfigValue(%q) error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("evalConfigValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEvalConfigValueShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell syntax; skipping on Windows")
	}
	tests := map[string]string{
		"`echo hello`":                    "hello",
		"  `echo hello`  ":                "hello",
		"`printf 'secret\\n' | head -1`":  "secret",
		"`echo one; echo two`":            "one\ntwo",
		"``":                              "",
	}
	for input, want := range tests {
		got, err := evalConfigValue(input)
		if err != nil {
			t.Errorf("evalConfigValue(%q) error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("evalConfigValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEvalConfigValueShellError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell syntax; skipping on Windows")
	}
	_, err := evalConfigValue("`exit 3`")
	if err == nil {
		t.Fatal("expected error from failing shell command, got nil")
	}
}

func TestEvalConfigValueRespectsSHELL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell syntax; skipping on Windows")
	}
	t.Setenv("SHELL", "/bin/sh")
	got, err := evalConfigValue("`echo via-sh`")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "via-sh" {
		t.Errorf("got %q, want %q", got, "via-sh")
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

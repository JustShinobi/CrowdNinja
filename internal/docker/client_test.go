package docker

import (
	"testing"
)

func TestStripControlCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No control characters",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "ANSI color codes",
			input:    "\x1b[31mRed\x1b[0m Text",
			expected: "Red Text",
		},
		{
			name:     "Complex ANSI codes",
			input:    "\x1b[1;31mBold Red\x1b[0m",
			expected: "Bold Red",
		},
		{
			name:     "JSON with ANSI",
			input:    "\x1b[32m{\"enrolled\": true}\x1b[0m",
			expected: "{\"enrolled\": true}",
		},
		{
			name:     "Newlines and tabs",
			input:    "Line 1\nLine 2\tTabbed",
			expected: "Line 1\nLine 2\tTabbed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripControlCharacters(tt.input)
			if result != tt.expected {
				t.Errorf("stripControlCharacters(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCloudNativeRuntimeModeAndOperations(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RUNTIME_MODE", "lapi")
	t.Setenv("CROWDSEC_FS_ROOT", dir)

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if !c.isCloudNative() || c.RuntimeMode() != "lapi" {
		t.Fatalf("expected Cloud-Native lapi mode, got %q", c.RuntimeMode())
	}

	// Test ExecCommand in Cloud-Native mode without Docker socket
	out, err := c.ExecCommand("crowdsec", []string{"echo", "crowdninja-ok"})
	if err != nil {
		t.Fatalf("ExecCommand failed: %v", err)
	}
	if out != "crowdninja-ok\n" {
		t.Fatalf("unexpected ExecCommand output: %q", out)
	}

	// Test WriteFileToContainer, FileExists, ReadFileFromContainer, and AppendLineToFileInContainer
	yamlPath := "/etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml"
	initialYAML := "name: crowdsecurity/whitelists\nwhitelist:\n  reason: \"trusted\"\n  ip:\n    - \"127.0.0.1\"\n"
	if err := c.WriteFileToContainer("crowdsec", yamlPath, []byte(initialYAML)); err != nil {
		t.Fatalf("WriteFileToContainer failed: %v", err)
	}
	exists, err := c.FileExists("crowdsec", yamlPath)
	if err != nil || !exists {
		t.Fatalf("FileExists failed: exists=%v err=%v", exists, err)
	}
	if err := c.AppendLineToFileInContainer("crowdsec", yamlPath, "ip:", "    - \"10.20.0.0/16\""); err != nil {
		t.Fatalf("AppendLineToFileInContainer failed: %v", err)
	}
	readBack, err := c.ReadFileFromContainer("crowdsec", yamlPath)
	if err != nil {
		t.Fatalf("ReadFileFromContainer failed: %v", err)
	}
	if readBack == initialYAML {
		t.Fatalf("expected appended IP in %q", readBack)
	}

	// Test synthetic container listing and inspection
	containers, err := c.ListContainers(true)
	if err != nil || len(containers) == 0 {
		t.Fatalf("ListContainers failed: len=%d err=%v", len(containers), err)
	}
	running, err := c.IsContainerRunning("crowdsec")
	if err != nil || !running {
		t.Fatalf("IsContainerRunning failed: running=%v err=%v", running, err)
	}
}

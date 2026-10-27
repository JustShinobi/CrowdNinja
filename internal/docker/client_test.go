package docker

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

	// Test kill SIGHUP 1 interception (CRIT-03 guard)
	if _, err := c.ExecCommand("crowdsec", []string{"kill", "-SIGHUP", "1"}); err != nil {
		t.Fatalf("expected kill SIGHUP 1 to be safely intercepted, got: %v", err)
	}

	// Test nil-safe image & exec methods in Cloud-Native mode (CRIT-01 guard)
	if err := c.ValidateImageTag("crowdsecurity/crowdsec", "latest"); err != nil {
		t.Fatalf("ValidateImageTag failed: %v", err)
	}
	if _, err := c.GetLocalImageDigest("crowdsecurity/crowdsec", "latest"); err != nil {
		t.Fatalf("GetLocalImageDigest failed: %v", err)
	}
	if _, err := ExecInteractive(c, "crowdsec", []string{"/bin/sh"}, nil); err == nil {
		t.Fatalf("expected ExecInteractive to return error in Cloud-Native mode")
	}

	// Test Docker multiplexed framing in wrapDockerMultiplexedStream (CRIT-04 guard)
	stream := wrapDockerMultiplexedStream("2026-10-26T12:00:00Z info test log\n")
	defer stream.Close()
	hdr := make([]byte, 8)
	if _, err := stream.Read(hdr); err != nil {
		t.Fatalf("stream.Read header failed: %v", err)
	}
	frameLen := int(hdr[4])<<24 | int(hdr[5])<<16 | int(hdr[6])<<8 | int(hdr[7])
	if hdr[0] != 1 || frameLen != 35 {
		t.Fatalf("unexpected Docker frame header: type=%d len=%d", hdr[0], frameLen)
	}
}

func TestMultiLAPIInstancesSupport(t *testing.T) {
	t.Setenv("LAPI_INSTANCES", "k3s-prod=http://crowdsec-service:8080|/etc/crowdsec/config.yaml,edge-dmz=http://10.20.10.10:8080|/etc/crowdsec/edge.yaml")

	mhc, err := NewMultiHostClient("")
	if err != nil {
		t.Fatalf("NewMultiHostClient failed: %v", err)
	}
	defer mhc.Close()

	hosts := mhc.ListHosts()
	if len(hosts) != 2 || mhc.DefaultHostID() != "k3s-prod" {
		t.Fatalf("unexpected LAPI instances: %+v default=%s", hosts, mhc.DefaultHostID())
	}

	mhc.RegisterLAPIInstance("branch-01", "http://10.30.0.10:8080", "/etc/crowdsec/branch.yaml")
	if len(mhc.ListHosts()) != 3 {
		t.Fatalf("expected 3 LAPI instances after RegisterLAPIInstance")
	}

	branchClient, err := mhc.GetClient("branch-01")
	if err != nil || branchClient.lapiURL != "http://10.30.0.10:8080" {
		t.Fatalf("unexpected branch-01 client: %+v err=%v", branchClient, err)
	}

	if err := mhc.RemoveLAPIInstance("branch-01"); err != nil {
		t.Fatalf("RemoveLAPIInstance failed: %v", err)
	}
	if len(mhc.ListHosts()) != 2 {
		t.Fatalf("expected 2 LAPI instances after RemoveLAPIInstance")
	}
}

func TestKubernetesAutoReloadOnRestartAndSIGHUP(t *testing.T) {
	var patchCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			atomic.AddInt32(&patchCount, 1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	t.Setenv("RUNTIME_MODE", "kubernetes")
	t.Setenv("KUBERNETES_API_URL", srv.URL)
	t.Setenv("KUBERNETES_BEARER_TOKEN", "test-sa-token")
	t.Setenv("KUBERNETES_NAMESPACE", "k3s-prod-security")
	t.Setenv("KUBERNETES_LAPI_DEPLOYMENT", "crowdsec-lapi")
	t.Setenv("KUBERNETES_AGENT_DAEMONSET", "crowdsec-agent")

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if err := c.RestartContainer("crowdsec"); err != nil {
		t.Fatalf("RestartContainer failed: %v", err)
	}
	if got := atomic.LoadInt32(&patchCount); got != 2 {
		t.Fatalf("expected 2 PATCH requests (Deployment + DaemonSet), got %d", got)
	}

	if _, err := c.ExecCommand("crowdsec", []string{"kill", "-SIGHUP", "1"}); err != nil {
		t.Fatalf("ExecCommand SIGHUP failed: %v", err)
	}
	if got := atomic.LoadInt32(&patchCount); got != 4 {
		t.Fatalf("expected 4 PATCH requests after SIGHUP, got %d", got)
	}
}

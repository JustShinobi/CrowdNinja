package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

var safeServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// ResolveRuntimeMode determines whether CrowdNinja should use the Docker socket
// ("docker") or the Cloud-Native LAPI/Kubernetes driver ("lapi" / "kubernetes").
func ResolveRuntimeMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RUNTIME_MODE")))
	switch mode {
	case "lapi", "local":
		return "lapi"
	case "kubernetes", "k8s":
		return "kubernetes"
	case "docker":
		return "docker"
	default:
		if os.Getenv("DOCKER_HOST") != "" {
			return "docker"
		}
		if info, err := os.Stat("/var/run/docker.sock"); err == nil && !info.IsDir() {
			return "docker"
		}
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			return "kubernetes"
		}
		return "lapi"
	}
}

func (c *Client) isCloudNative() bool {
	return c != nil && (c.mode == "lapi" || c.mode == "kubernetes" || c.cli == nil)
}

// RuntimeMode returns the active runtime driver name ("docker", "lapi", or "kubernetes").
func (c *Client) RuntimeMode() string {
	if c == nil || c.mode == "" {
		return "docker"
	}
	return c.mode
}

func resolveLocalPath(containerPath string) string {
	cleaned := filepath.Clean("/" + strings.TrimSpace(containerPath))
	rootPrefix := strings.TrimSpace(os.Getenv("CROWDSEC_FS_ROOT"))
	if rootPrefix != "" {
		return filepath.Join(rootPrefix, cleaned)
	}
	return cleaned
}

func (c *Client) execLocalCommand(cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("empty command")
	}

	bin := cmd[0]
	args := append([]string{}, cmd[1:]...)

	// Prevent self-termination (e.g. "kill -SIGHUP 1" intended for a separate CrowdSec container)
	if bin == "kill" || bin == "/bin/kill" || bin == "/usr/bin/kill" {
		return "", nil
	}

	// If cat/tail/rm/find are invoked with container paths while CROWDSEC_FS_ROOT is set, remap paths
	if (bin == "cat" || bin == "tail" || bin == "rm" || bin == "find") && os.Getenv("CROWDSEC_FS_ROOT") != "" {
		for i, a := range args {
			if strings.HasPrefix(a, "/") {
				args[i] = resolveLocalPath(a)
			}
		}
	}

	if bin == "cscli" {
		if customBin := strings.TrimSpace(os.Getenv("CROWDSEC_CSCLI_BIN")); customBin != "" {
			bin = customBin
		}
		cfgFile := strings.TrimSpace(os.Getenv("CROWDSEC_CONFIG_FILE"))
		if cfgFile == "" {
			cfgFile = "/etc/crowdsec/config.yaml"
		}
		if _, err := os.Stat(cfgFile); err == nil && !hasConfigFlag(args) {
			args = append([]string{"-c", cfgFile}, args...)
		}
	}

	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	execCmd := exec.CommandContext(ctx, bin, args...)
	execCmd.Env = append(os.Environ(), "TERM=dumb", "NO_COLOR=1")

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err := execCmd.Run()
	cleanOut := stripControlCharacters(stdout.String())
	if err != nil {
		errMsg := strings.TrimSpace(stripControlCharacters(stderr.String()))
		if errMsg == "" {
			errMsg = err.Error()
		}
		return cleanOut, fmt.Errorf("command %q failed: %s", strings.Join(cmd, " "), errMsg)
	}
	return cleanOut, nil
}

func hasConfigFlag(args []string) bool {
	for _, a := range args {
		if a == "-c" || a == "--config" || strings.HasPrefix(a, "-c=") || strings.HasPrefix(a, "--config=") {
			return true
		}
	}
	return false
}

func (c *Client) writeLocalFile(filePath string, content []byte) error {
	target := resolveLocalPath(filePath)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", target, err)
	}
	if err := os.WriteFile(target, content, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", target, err)
	}
	return nil
}

func (c *Client) readLocalFile(filePath string) (string, error) {
	target := resolveLocalPath(filePath)
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", target, err)
	}
	return string(data), nil
}

func (c *Client) localFileExists(filePath string) (bool, error) {
	target := resolveLocalPath(filePath)
	_, err := os.Stat(target)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (c *Client) copyFromLocalFile(srcPath string) (io.ReadCloser, error) {
	target := resolveLocalPath(srcPath)
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: filepath.Base(target),
		Mode: 0644,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func (c *Client) copyToLocalFile(dstPath string, content io.Reader) error {
	baseDir := filepath.Clean(resolveLocalPath(dstPath))
	tr := tar.NewReader(io.LimitReader(content, 20*1024*1024))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if strings.Contains(hdr.Name, "..") {
			return fmt.Errorf("invalid tar entry path: %s", hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 10*1024*1024))
		if err != nil {
			return err
		}
		target := filepath.Join(baseDir, filepath.Clean("/"+hdr.Name))
		if !strings.HasPrefix(target, baseDir+string(os.PathSeparator)) && target != baseDir {
			return fmt.Errorf("tar entry escapes destination: %s", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) pingCloudNative() error {
	lapiURL := strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_URL"))
	if lapiURL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, strings.TrimRight(lapiURL, "/")+"/v1/heartbeat", nil)
	if err != nil {
		return nil
	}
	httpClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloud-native LAPI ping failed (%s): %w", lapiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("cloud-native LAPI returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) syntheticContainers() []types.Container {
	crowdsecName := os.Getenv("CROWDSEC_CONTAINER_NAME")
	if crowdsecName == "" {
		crowdsecName = "crowdsec"
	}
	traefikName := os.Getenv("TRAEFIK_CONTAINER_NAME")
	if traefikName == "" {
		traefikName = "traefik"
	}
	now := time.Now().Unix()
	return []types.Container{
		{
			ID:      "cloudnative-" + crowdsecName,
			Names:   []string{"/" + crowdsecName},
			Image:   "crowdsecurity/crowdsec:cloudnative",
			State:   "running",
			Status:  "Up (Cloud-Native " + c.mode + " mode)",
			Created: now,
		},
		{
			ID:      "cloudnative-" + traefikName,
			Names:   []string{"/" + traefikName},
			Image:   "traefik:cloudnative",
			State:   "running",
			Status:  "Up (Cloud-Native " + c.mode + " mode)",
			Created: now,
		},
	}
}

func (c *Client) inspectSyntheticContainer(name string) (*types.ContainerJSON, error) {
	startedAt := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	return &types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   "cloudnative-" + name,
			Name: "/" + name,
			State: &types.ContainerState{
				Status:     "running",
				Running:    true,
				StartedAt:  startedAt,
				FinishedAt: "0001-01-01T00:00:00Z",
			},
		},
		Mounts: []types.MountPoint{},
		Config: &container.Config{
			Image: name + ":cloudnative",
		},
	}, nil
}

// wrapDockerMultiplexedStream wraps plain-text log lines in Docker's 8-byte stdcopy
// stream headers ([1, 0, 0, 0, size_be32]) so callers using stdcopy or raw 8-byte
// header readers (such as StreamLogs) work identically in Cloud-Native mode.
func wrapDockerMultiplexedStream(logs string) io.ReadCloser {
	var buf bytes.Buffer
	if logs != "" {
		for _, line := range strings.SplitAfter(logs, "\n") {
			if line == "" {
				continue
			}
			b := []byte(line)
			n := len(b)
			hdr := [8]byte{1, 0, 0, 0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
			buf.Write(hdr[:])
			buf.Write(b)
		}
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes()))
}

func (c *Client) fetchCloudNativeLogs(containerName, tail string) (string, error) {
	limit := 100
	if n, err := strconv.Atoi(tail); err == nil && n > 0 {
		limit = n
	}
	if limit > 5000 {
		limit = 5000
	}

	safeName := strings.TrimSpace(containerName)
	if !safeServiceNameRe.MatchString(safeName) {
		safeName = "crowdsec"
	}

	provider := strings.ToLower(strings.TrimSpace(os.Getenv("LOGS_PROVIDER")))
	vlogsURL := strings.TrimSpace(os.Getenv("VICTORIALOGS_URL"))
	lokiURL := strings.TrimSpace(os.Getenv("LOKI_URL"))

	if provider == "victorialogs" || (provider == "" && vlogsURL != "") {
		if vlogsURL != "" {
			return c.queryVictoriaLogs(vlogsURL, safeName, limit)
		}
	}
	if provider == "loki" || (provider == "" && lokiURL != "") {
		if lokiURL != "" {
			return c.queryLokiLogs(lokiURL, safeName, limit)
		}
	}

	logFile := os.Getenv("LOG_FILE")
	if strings.Contains(strings.ToLower(safeName), "traefik") {
		if tfLog := os.Getenv("TRAEFIK_ACCESS_LOG"); tfLog != "" {
			logFile = tfLog
		}
	}
	if logFile != "" {
		if data, err := os.ReadFile(resolveLocalPath(logFile)); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) > limit {
				lines = lines[len(lines)-limit:]
			}
			return strings.Join(lines, "\n"), nil
		}
	}
	return "", nil
}

func (c *Client) queryVictoriaLogs(baseURL, serviceName string, limit int) (string, error) {
	if !safeServiceNameRe.MatchString(serviceName) {
		return "", fmt.Errorf("invalid service name %q", serviceName)
	}
	query := fmt.Sprintf("_time:1h %q | limit %d", serviceName, limit)
	endpoint := strings.TrimRight(baseURL, "/") + "/select/logsql/query?query=" + url.QueryEscape(query)

	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("victorialogs status %d: %s", resp.StatusCode, string(body))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}

	var outLines []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var item map[string]interface{}
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			ts, _ := item["_time"].(string)
			msg, _ := item["_msg"].(string)
			if msg != "" {
				outLines = append(outLines, fmt.Sprintf("%s info %s", ts, msg))
				continue
			}
		}
		outLines = append(outLines, line)
	}
	return strings.Join(outLines, "\n"), nil
}

func (c *Client) queryLokiLogs(baseURL, serviceName string, limit int) (string, error) {
	if !safeServiceNameRe.MatchString(serviceName) {
		return "", fmt.Errorf("invalid service name %q", serviceName)
	}
	logql := fmt.Sprintf(`{app=~".*%s.*"}`, regexp.QuoteMeta(serviceName))
	params := url.Values{}
	params.Set("query", logql)
	params.Set("limit", strconv.Itoa(limit))
	endpoint := strings.TrimRight(baseURL, "/") + "/loki/api/v1/query_range?" + params.Encode()

	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("loki status %d: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		Data struct {
			Result []struct {
				Values [][]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&parsed); err != nil {
		return "", err
	}

	var outLines []string
	for _, stream := range parsed.Data.Result {
		for _, pair := range stream.Values {
			if len(pair) >= 2 {
				outLines = append(outLines, pair[1])
			}
		}
	}
	return strings.Join(outLines, "\n"), nil
}

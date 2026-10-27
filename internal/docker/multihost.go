package docker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"crowdsec-manager/internal/logger"

	"github.com/docker/docker/client"
)

// HostInfo describes a configured Docker host
type HostInfo struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	IsLocal  bool   `json:"is_local"`
}

// MultiHostClient manages connections to multiple Docker hosts
type MultiHostClient struct {
	mu       sync.RWMutex
	clients  map[string]*Client
	hosts    []HostInfo
	defaultID string
}

// NewMultiHostClient creates a MultiHostClient from a config string.
// Format: "id:endpoint,id:endpoint" e.g. "local:unix:///var/run/docker.sock,remote:tcp://192.168.1.10:2375"
// If hostsConfig is empty, falls back to a single default client using DOCKER_HOST env var.
func NewMultiHostClient(hostsConfig string) (*MultiHostClient, error) {
	mhc := &MultiHostClient{
		clients: make(map[string]*Client),
	}

	if hostsConfig == "" {
		// Check if LAPI_INSTANCES is set for Multi-LAPI Cloud-Native mode
		if lapiInstances := strings.TrimSpace(os.Getenv("LAPI_INSTANCES")); lapiInstances != "" {
			if err := mhc.registerLAPIInstancesString(lapiInstances); err != nil {
				return nil, err
			}
			logger.Info("Multi-LAPI client initialized", "instances", len(mhc.clients), "default", mhc.defaultID)
			return mhc, nil
		}

		// Fallback: single host from environment (DOCKER_HOST, default socket, or Cloud-Native LAPI/Kubernetes mode)
		c, err := NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create default runtime client: %w", err)
		}
		endpoint := "unix:///var/run/docker.sock"
		if c.isCloudNative() {
			endpoint = strings.TrimSpace(os.Getenv("CROWDSEC_LAPI_URL"))
			if endpoint == "" {
				endpoint = "cloudnative://" + c.mode
			}
			c.lapiURL = os.Getenv("CROWDSEC_LAPI_URL")
			c.configFile = os.Getenv("CROWDSEC_CONFIG_FILE")
		}
		mhc.clients["local"] = c
		mhc.defaultID = "local"
		mhc.hosts = []HostInfo{{ID: "local", Endpoint: endpoint, IsLocal: true}}
		logger.Info("Runtime client initialized", "mode", c.RuntimeMode(), "endpoint", endpoint)
		return mhc, nil
	}

	// Parse "id:endpoint,id:endpoint" format
	entries := strings.Split(hostsConfig, ",")
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid DOCKER_HOSTS entry %q: expected id:endpoint", entry)
		}

		hostID := strings.TrimSpace(parts[0])
		endpoint := strings.TrimSpace(parts[1])

		if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
			lapiURL, cfgPath := splitLAPIEndpoint(endpoint)
			mhc.clients[hostID] = &Client{
				cli:        nil,
				ctx:        context.Background(),
				mode:       "lapi",
				lapiURL:    lapiURL,
				configFile: cfgPath,
			}
			mhc.hosts = append(mhc.hosts, HostInfo{ID: hostID, Endpoint: lapiURL, IsLocal: false})
			if i == 0 {
				mhc.defaultID = hostID
			}
			logger.Info("Registered Cloud-Native LAPI instance", "id", hostID, "lapi_url", lapiURL)
			continue
		}

		isLocal := strings.HasPrefix(endpoint, "unix://")

		cli, err := client.NewClientWithOpts(
			client.WithHost(endpoint),
			client.WithAPIVersionNegotiation(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create docker client for host %q (%s): %w", hostID, endpoint, err)
		}

		mhc.clients[hostID] = &Client{cli: cli, ctx: context.Background(), mode: "docker"}
		mhc.hosts = append(mhc.hosts, HostInfo{ID: hostID, Endpoint: endpoint, IsLocal: isLocal})

		if i == 0 {
			mhc.defaultID = hostID
		}

		logger.Info("Registered Docker host", "id", hostID, "endpoint", endpoint)
	}

	if len(mhc.clients) == 0 {
		return nil, fmt.Errorf("no valid Docker hosts configured in DOCKER_HOSTS")
	}

	logger.Info("Multi-host Docker client initialized", "hosts", len(mhc.clients), "default", mhc.defaultID)
	return mhc, nil
}

// GetClient returns the Docker client for the given host ID.
// Returns the default client if hostID is empty.
func (m *MultiHostClient) GetClient(hostID string) (*Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hostID == "" {
		hostID = m.defaultID
	}

	c, ok := m.clients[hostID]
	if !ok {
		return nil, fmt.Errorf("unknown docker host: %q", hostID)
	}
	return c, nil
}

// DefaultClient returns the default Docker client
func (m *MultiHostClient) DefaultClient() *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[m.defaultID]
}

// ListHosts returns all configured host info with connectivity status
func (m *MultiHostClient) ListHosts() []HostInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]HostInfo, len(m.hosts))
	copy(result, m.hosts)
	return result
}

// DefaultHostID returns the default host identifier
func (m *MultiHostClient) DefaultHostID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultID
}

// Close closes all Docker client connections
func (m *MultiHostClient) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, c := range m.clients {
		if err := c.Close(); err != nil {
			logger.Error("Failed to close Docker client", "host", id, "error", err)
		}
	}
}

func splitLAPIEndpoint(raw string) (string, string) {
	parts := strings.SplitN(raw, "|", 2)
	lapiURL := strings.TrimSpace(parts[0])
	var cfgPath string
	if len(parts) == 2 {
		cfgPath = strings.TrimSpace(parts[1])
	}
	return lapiURL, cfgPath
}

func (m *MultiHostClient) registerLAPIInstancesString(raw string) error {
	entries := strings.Split(raw, ",")
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var hostID, endpoint string
		if eqIdx := strings.Index(entry, "="); eqIdx > 0 {
			hostID = strings.TrimSpace(entry[:eqIdx])
			endpoint = strings.TrimSpace(entry[eqIdx+1:])
		} else if colIdx := strings.Index(entry, ":"); colIdx > 0 {
			hostID = strings.TrimSpace(entry[:colIdx])
			endpoint = strings.TrimSpace(entry[colIdx+1:])
		} else {
			return fmt.Errorf("invalid LAPI_INSTANCES entry %q: expected id=http://host:8080[|/path/config.yaml]", entry)
		}
		lapiURL, cfgPath := splitLAPIEndpoint(endpoint)
		if hostID == "" || lapiURL == "" {
			return fmt.Errorf("invalid LAPI_INSTANCES entry %q", entry)
		}
		m.RegisterLAPIInstance(hostID, lapiURL, cfgPath)
		if i == 0 {
			m.defaultID = hostID
		}
	}
	if len(m.clients) == 0 {
		return fmt.Errorf("no valid LAPI instances configured in LAPI_INSTANCES")
	}
	return nil
}

// RegisterLAPIInstance dynamically adds or updates a Cloud-Native CrowdSec LAPI instance at runtime.
func (m *MultiHostClient) RegisterLAPIInstance(id, lapiURL, configFile string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	lapiURL = strings.TrimSpace(lapiURL)
	configFile = strings.TrimSpace(configFile)

	m.clients[id] = &Client{
		cli:        nil,
		ctx:        context.Background(),
		mode:       "lapi",
		lapiURL:    lapiURL,
		configFile: configFile,
	}

	found := false
	for i := range m.hosts {
		if m.hosts[i].ID == id {
			m.hosts[i].Endpoint = lapiURL
			found = true
			break
		}
	}
	if !found {
		m.hosts = append(m.hosts, HostInfo{ID: id, Endpoint: lapiURL, IsLocal: id == m.defaultID})
	}
	if m.defaultID == "" {
		m.defaultID = id
	}
}

// RemoveLAPIInstance removes a dynamically registered LAPI instance (cannot remove default instance).
func (m *MultiHostClient) RemoveLAPIInstance(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == m.defaultID {
		return fmt.Errorf("cannot remove default instance %q", id)
	}
	if _, ok := m.clients[id]; !ok {
		return fmt.Errorf("instance %q not found", id)
	}
	delete(m.clients, id)
	filtered := make([]HostInfo, 0, len(m.hosts))
	for _, h := range m.hosts {
		if h.ID != id {
			filtered = append(filtered, h)
		}
	}
	m.hosts = filtered
	return nil
}

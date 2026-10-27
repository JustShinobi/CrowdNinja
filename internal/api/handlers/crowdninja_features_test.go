package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"

	"github.com/gin-gonic/gin"
)

func TestMatchStructuredQuery(t *testing.T) {
	record := map[string]string{
		"ip":       "198.51.100.42",
		"scenario": "crowdsecurity/http-probing",
		"origin":   "crowdsec",
		"country":  "CN",
		"asn":      "AS4134",
	}

	tests := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"198.51.100.42", true},
		{"ip:198.51.100.42 AND origin:crowdsec", true},
		{"ip:198.51.100.42 AND -origin:CAPI", true},
		{"ip:198.51.100.42 AND NOT origin:crowdsec", false},
		{"country:US OR country:CN", true},
		{"country:US OR country:DE", false},
		{`scenario:"http-probing" AND asn:AS4134`, true},
	}

	for _, tc := range tests {
		got := MatchStructuredQuery(tc.query, record)
		if got != tc.want {
			t.Errorf("MatchStructuredQuery(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}

func TestPersistentASNRulesAndExceptions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	db, err := database.New(dir + "/test.db")
	if err != nil {
		t.Fatalf("database.New failed: %v", err)
	}
	defer db.Close()

	// Test tombstones as well
	if err := db.AddDeletionTombstone("alert", "42", "198.51.100.1"); err != nil {
		t.Fatalf("AddDeletionTombstone failed: %v", err)
	}
	tombstones, err := db.ActiveTombstoneIDs("alert")
	if err != nil || !tombstones["42"] {
		t.Fatalf("ActiveTombstoneIDs failed: %v %v", tombstones, err)
	}

	t.Setenv("RUNTIME_MODE", "lapi")
	runtimeClient, err := docker.NewClient()
	if err != nil {
		t.Fatalf("docker.NewClient failed: %v", err)
	}

	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}
	r := gin.New()
	r.POST("/api/asn/rules", UpsertASNRule(db))
	r.GET("/api/asn/rules", ListASNRules(db))
	r.POST("/api/asn/exceptions", AddASNException(db))
	r.POST("/api/asn/evaluate", EvaluateASNEvent(db, runtimeClient, cfg))

	// 1. Create a dry-run ASN rule for 14061
	ruleBody, _ := json.Marshal(database.ASNRule{
		ASN:      "14061",
		ASName:   "DigitalOcean",
		Action:   "ban",
		Duration: "168h",
		DryRun:   true,
		Enabled:  true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/asn/rules", bytes.NewReader(ruleBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/asn/rules status=%d body=%s", w.Code, w.Body.String())
	}

	// 2. Add CIDR exception 198.51.100.0/24
	excBody, _ := json.Marshal(database.ASNException{
		ASN:      "AS14061",
		IPOrCIDR: "198.51.100.0/24",
		Note:     "Trusted subnet",
	})
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/asn/exceptions", bytes.NewReader(excBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/asn/exceptions status=%d body=%s", w.Code, w.Body.String())
	}

	// 3. Evaluate excepted IP -> should report excepted=true
	evalExc, _ := json.Marshal(ASNEvaluateRequest{IP: "198.51.100.25", ASN: "14061"})
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/asn/evaluate", bytes.NewReader(evalExc))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"excepted":true`)) {
		t.Fatalf("expected excepted=true, got %s", w.Body.String())
	}

	// 4. Evaluate non-excepted IP -> should trigger dry_run=true match
	evalHit, _ := json.Marshal(ASNEvaluateRequest{IP: "203.0.113.9", ASN: "AS14061"})
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/asn/evaluate", bytes.NewReader(evalHit))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"dry_run":true`)) {
		t.Fatalf("expected dry_run=true match, got %s", w.Body.String())
	}
}

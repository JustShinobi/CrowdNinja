package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// ListASNRules returns all persistent ASN response rules.
func ListASNRules(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		rules, err := db.ListASNRules()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to list ASN rules: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    rules,
		})
	}
}

// UpsertASNRule creates or updates a persistent ASN ban rule.
func UpsertASNRule(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req database.ASNRule
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid ASN rule payload: " + err.Error(),
			})
			return
		}
		req.ASN = normalizeASN(req.ASN)
		if req.ASN == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "ASN is required (e.g. AS14061 or 14061)",
			})
			return
		}
		if err := db.UpsertASNRule(&req); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to save ASN rule: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "ASN rule saved",
			Data:    req,
		})
	}
}

// DeleteASNRule deletes a persistent ASN rule.
func DeleteASNRule(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		asn := normalizeASN(c.Param("asn"))
		if asn == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "ASN parameter is required",
			})
			return
		}
		if err := db.DeleteASNRule(asn); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to delete ASN rule: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "ASN rule deleted",
		})
	}
}

// ListASNExceptions returns ASN IP/CIDR exceptions.
func ListASNExceptions(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		asn := normalizeASN(c.Query("asn"))
		excs, err := db.ListASNExceptions(asn)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to list ASN exceptions: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    excs,
		})
	}
}

// AddASNException adds an IP/CIDR exception for a persistent ASN rule.
func AddASNException(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req database.ASNException
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid ASN exception payload: " + err.Error(),
			})
			return
		}
		req.ASN = normalizeASN(req.ASN)
		if req.ASN == "" || strings.TrimSpace(req.IPOrCIDR) == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Both asn and ip_or_cidr are required",
			})
			return
		}
		if err := db.AddASNException(&req); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to add ASN exception: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "ASN exception added",
			Data:    req,
		})
	}
}

// DeleteASNException removes an ASN exception by ID.
func DeleteASNException(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid exception ID",
			})
			return
		}
		if err := db.DeleteASNException(id); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to delete ASN exception: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "ASN exception deleted",
		})
	}
}

// ASNEvaluateRequest is the payload for evaluating an observed IP+ASN against persistent ASN rules.
type ASNEvaluateRequest struct {
	IP  string `json:"ip"`
	ASN string `json:"asn"`
}

// EvaluateASNEvent checks if an IP+ASN matches an enabled ASN rule (excluding IP/CIDR exceptions)
// and applies a CrowdSec decision when dry_run is false.
func EvaluateASNEvent(db *database.Database, dockerClient *docker.Client, cfg *config.Config, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req ASNEvaluateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid evaluation payload: " + err.Error(),
			})
			return
		}
		asn := normalizeASN(req.ASN)
		ip := strings.TrimSpace(req.IP)
		if asn == "" || ip == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Both ip and asn are required",
			})
			return
		}

		rules, err := db.ListASNRules()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		var matchedRule *database.ASNRule
		for i := range rules {
			if rules[i].ASN == asn && rules[i].Enabled {
				matchedRule = &rules[i]
				break
			}
		}
		if matchedRule == nil {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: "No active ASN rule matched",
				Data:    gin.H{"matched": false},
			})
			return
		}

		exceptions, _ := db.ListASNExceptions(asn)
		if isIPExcepted(ip, exceptions) {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: "IP matched ASN exception list; skipping ban",
				Data:    gin.H{"matched": true, "excepted": true, "asn": asn, "ip": ip},
			})
			return
		}

		if matchedRule.DryRun {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: "Dry-run simulation: IP would be banned by persistent ASN rule",
				Data:    gin.H{"matched": true, "excepted": false, "dry_run": true, "rule": matchedRule, "ip": ip},
			})
			return
		}

		cmd := []string{
			"cscli", "decisions", "add",
			"--ip", ip,
			"--duration", matchedRule.Duration,
			"--type", matchedRule.Action,
			"--reason", fmt.Sprintf("%s (%s)", matchedRule.Reason, asn),
		}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to apply ASN decision: " + err.Error(),
				Details: output,
			})
			return
		}

		invalidateCrowdSecDataCache(ttlCache...)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Persistent ASN ban applied",
			Data:    gin.H{"matched": true, "excepted": false, "dry_run": false, "rule": matchedRule, "ip": ip, "output": output},
		})
	}
}

func normalizeASN(asn string) string {
	s := strings.ToUpper(strings.TrimSpace(asn))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "AS") {
		s = "AS" + s
	}
	return s
}

func isIPExcepted(ipStr string, exceptions []database.ASNException) bool {
	parsedIP := net.ParseIP(strings.TrimSpace(ipStr))
	for _, exc := range exceptions {
		candidate := strings.TrimSpace(exc.IPOrCIDR)
		if candidate == ipStr {
			return true
		}
		if parsedIP != nil && strings.Contains(candidate, "/") {
			if _, ipNet, err := net.ParseCIDR(candidate); err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		}
	}
	return false
}

// MatchStructuredQuery evaluates a CrowdSec Web UI style structured query
// (supports field:value, AND, OR, NOT, unary -field:value, and free text)
// against a record map.
func MatchStructuredQuery(query string, fields map[string]string) bool {
	q := strings.TrimSpace(query)
	if q == "" {
		return true
	}

	// Split by top-level OR groups first
	orGroups := splitByOperator(q, "OR")
	for _, group := range orGroups {
		if matchAndGroup(group, fields) {
			return true
		}
	}
	return false
}

func matchAndGroup(group string, fields map[string]string) bool {
	tokens := tokenizeSearch(group)
	negateNext := false

	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		if upper == "AND" {
			continue
		}
		if upper == "NOT" {
			negateNext = !negateNext
			continue
		}

		negated := negateNext
		negateNext = false

		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			negated = !negated
			tok = tok[1:]
		}

		matched := matchSingleTerm(tok, fields)
		if negated {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchSingleTerm(term string, fields map[string]string) bool {
	term = strings.Trim(term, `"`)
	if idx := strings.Index(term, ":"); idx > 0 {
		key := strings.ToLower(strings.TrimSpace(term[:idx]))
		val := strings.ToLower(strings.Trim(strings.TrimSpace(term[idx+1:]), `"`))
		if actual, ok := fields[key]; ok {
			return strings.Contains(strings.ToLower(actual), val)
		}
		return false
	}

	needle := strings.ToLower(term)
	for _, v := range fields {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

func splitByOperator(q, op string) []string {
	tokens := tokenizeSearch(q)
	var groups []string
	var current []string
	for _, t := range tokens {
		if strings.EqualFold(t, op) {
			if len(current) > 0 {
				groups = append(groups, strings.Join(current, " "))
				current = nil
			}
			continue
		}
		current = append(current, t)
	}
	if len(current) > 0 {
		groups = append(groups, strings.Join(current, " "))
	}
	if len(groups) == 0 {
		return []string{q}
	}
	return groups
}

func tokenizeSearch(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuotes := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' {
			inQuotes = !inQuotes
			cur.WriteByte(ch)
			continue
		}
		if (ch == ' ' || ch == '\t') && !inQuotes {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// QueryPromQLMetrics proxies or aggregates runtime CrowdSec metrics from Prometheus / VictoriaMetrics
// (ported from crowdsec-web-ui runtime metrics module).
func QueryPromQLMetrics(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		promURL := strings.TrimSpace(cfg.PrometheusURL)
		if promURL == "" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: "Prometheus/VictoriaMetrics URL not configured (PROMETHEUS_URL)",
				Data:    gin.H{"enabled": false},
			})
			return
		}

		query := strings.TrimSpace(c.Query("query"))
		if query == "" {
			query = `{__name__=~"cs_.*"}`
		}

		endpoint := strings.TrimRight(promURL, "/") + "/api/v1/query?query=" + url.QueryEscape(query)
		httpClient := &http.Client{Timeout: 8 * time.Second}
		resp, err := httpClient.Get(endpoint)
		if err != nil {
			c.JSON(http.StatusBadGateway, models.Response{
				Success: false,
				Error:   "Failed to query Prometheus/VictoriaMetrics: " + err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to read metrics response: " + err.Error(),
			})
			return
		}

		var parsed interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			c.JSON(http.StatusBadGateway, models.Response{
				Success: false,
				Error:   "Invalid JSON from metrics backend",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"enabled":  true,
				"provider": promURL,
				"result":   parsed,
			},
		})
	}
}

package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
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

var validASNPattern = regexp.MustCompile(`^AS\d{1,10}$`)

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
		if !validASNPattern.MatchString(req.ASN) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Valid ASN is required (e.g. AS14061 or 14061)",
			})
			return
		}
		if req.Action == "" {
			req.Action = "ban"
		}
		if req.Action != "ban" && req.Action != "captcha" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid action: must be 'ban' or 'captcha'",
			})
			return
		}
		if req.Duration == "" {
			req.Duration = "168h"
		}
		normDur, ok := NormalizeDuration(req.Duration)
		if !ok || normDur == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid duration format: " + req.Duration,
			})
			return
		}
		req.Duration = normDur

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
		if !validASNPattern.MatchString(asn) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Valid ASN parameter is required",
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
		req.IPOrCIDR = strings.TrimSpace(req.IPOrCIDR)
		if !validASNPattern.MatchString(req.ASN) || !isValidIPOrCIDR(req.IPOrCIDR) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Valid asn and ip_or_cidr (IP or CIDR) are required",
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
		if !validASNPattern.MatchString(asn) || net.ParseIP(ip) == nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Valid ip address and asn are required",
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

		exceptions, err := db.ListASNExceptions(asn)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to load ASN exceptions: " + err.Error(),
			})
			return
		}
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

		normDur, ok := NormalizeDuration(matchedRule.Duration)
		if !ok || normDur == "" {
			normDur = "168h"
		}
		action := matchedRule.Action
		if action != "ban" && action != "captcha" {
			action = "ban"
		}

		cmd := []string{
			"cscli", "decisions", "add",
			"--ip", ip,
			"--duration", normDur,
			"--type", action,
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
	if parsedIP == nil {
		return false
	}
	for _, exc := range exceptions {
		candidate := strings.TrimSpace(exc.IPOrCIDR)
		if candIP := net.ParseIP(candidate); candIP != nil && candIP.Equal(parsedIP) {
			return true
		}
		if strings.Contains(candidate, "/") {
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
	evaluatedTerms := 0

	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		if upper == "AND" {
			continue
		}
		if upper == "NOT" {
			negateNext = !negateNext
			continue
		}

		evaluatedTerms++
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
	return evaluatedTerms > 0 || !negateNext
}

func matchSingleTerm(term string, fields map[string]string) bool {
	term = strings.Trim(term, `"`)
	if idx := strings.Index(term, ":"); idx > 0 {
		key := strings.ToLower(strings.TrimSpace(term[:idx]))
		if actual, ok := fields[key]; ok {
			val := strings.ToLower(strings.Trim(strings.TrimSpace(term[idx+1:]), `"`))
			return strings.Contains(strings.ToLower(actual), val)
		}
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

var allowedPromQLSelectorRe = regexp.MustCompile(`\bcs_[a-zA-Z0-9_]+\b`)

// QueryPromQLMetrics proxies or aggregates runtime CrowdSec metrics from Prometheus / VictoriaMetrics
// (ported from crowdsec-web-ui runtime metrics module). Restricted to CrowdSec (cs_*) metrics.
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
		} else if !allowedPromQLSelectorRe.MatchString(query) && query != `{__name__=~"cs_.*"}` {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Only CrowdSec metrics (cs_*) may be queried via this endpoint",
			})
			return
		}

		endpoint := strings.TrimRight(promURL, "/") + "/api/v1/query?query=" + url.QueryEscape(query)
		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, endpoint, nil)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid PromQL request: " + err.Error(),
			})
			return
		}
		httpClient := &http.Client{Timeout: 8 * time.Second}
		resp, err := httpClient.Do(req)
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

package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

const (
	sessionCookieName = "crowdninja_session"
	stateCookieName   = "crowdninja_oidc_state"
	authUserContextKey = "crowdninja_user"
)

// AuthUser represents the authenticated operator identity (via OIDC or Trusted Proxy Headers).
type AuthUser struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	Provider string   `json:"provider"`
	Expires  int64    `json:"exp,omitempty"`
}

// AuthConfig holds OIDC and Reverse-Proxy Trusted Header SSO settings.
type AuthConfig struct {
	Enabled              bool
	Mode                 string // "oidc", "trusted-header"
	OIDCIssuerURL        string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCRedirectURL      string
	OIDCScopes           string
	OIDCAllowedGroups    []string
	TrustedHeaderEnabled bool
	TrustedUserHeader    string
	TrustedNameHeader    string
	TrustedEmailHeader   string
	TrustedGroupsHeader  string
	SessionSecret        []byte
}

type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

var (
	discoveryMu    sync.RWMutex
	discoveryCache = make(map[string]*oidcDiscoveryDoc)
)

// LoadAuthConfig loads OIDC/SSO configuration from environment variables.
func LoadAuthConfig() *AuthConfig {
	enabled := strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_ENABLED")), "true") ||
		strings.TrimSpace(os.Getenv("AUTH_ENABLED")) == "1"
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_MODE")))
	issuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL"))
	trustedHeader := strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_TRUSTED_HEADER_ENABLED")), "true") ||
		strings.TrimSpace(os.Getenv("AUTH_TRUSTED_HEADER_ENABLED")) == "1"

	if mode == "" {
		if issuer != "" {
			mode = "oidc"
		} else if trustedHeader {
			mode = "trusted-header"
		} else {
			mode = "none"
		}
	}

	scopes := strings.TrimSpace(os.Getenv("OIDC_SCOPES"))
	if scopes == "" {
		scopes = "openid profile email groups"
	}

	var allowedGroups []string
	for _, g := range strings.Split(os.Getenv("OIDC_ALLOWED_GROUPS"), ",") {
		if trimmed := strings.TrimSpace(g); trimmed != "" {
			allowedGroups = append(allowedGroups, trimmed)
		}
	}

	secretStr := strings.TrimSpace(os.Getenv("AUTH_SESSION_SECRET"))
	var secretBytes []byte
	if secretStr != "" {
		secretBytes = []byte(secretStr)
	} else {
		secretBytes = make([]byte, 32)
		_, _ = rand.Read(secretBytes)
	}

	return &AuthConfig{
		Enabled:              enabled,
		Mode:                 mode,
		OIDCIssuerURL:        issuer,
		OIDCClientID:         strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCClientSecret:     strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		OIDCRedirectURL:      strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
		OIDCScopes:           scopes,
		OIDCAllowedGroups:    allowedGroups,
		TrustedHeaderEnabled: trustedHeader || mode == "trusted-header",
		TrustedUserHeader:    defaultEnv("AUTH_TRUSTED_USER_HEADER", "Remote-User"),
		TrustedNameHeader:    defaultEnv("AUTH_TRUSTED_NAME_HEADER", "Remote-Name"),
		TrustedEmailHeader:   defaultEnv("AUTH_TRUSTED_EMAIL_HEADER", "Remote-Email"),
		TrustedGroupsHeader:  defaultEnv("AUTH_TRUSTED_GROUPS_HEADER", "Remote-Groups"),
		SessionSecret:        secretBytes,
	}
}

func defaultEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// AuthMiddleware enforces OIDC or Trusted-Header authentication on API routes when AUTH_ENABLED=true,
// and always populates the operator identity in Gin context when available.
func AuthMiddleware(cfg *AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg == nil {
			c.Next()
			return
		}

		// Public auth endpoints
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/auth/") || path == "/health" {
			if user := resolveRequestUser(c, cfg); user != nil {
				c.Set(authUserContextKey, user)
			}
			c.Next()
			return
		}

		user := resolveRequestUser(c, cfg)
		if user != nil {
			c.Set(authUserContextKey, user)
			c.Next()
			return
		}

		if !cfg.Enabled {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, models.Response{
			Success: false,
			Error:   "Authentication required",
			Data: gin.H{
				"auth_enabled": true,
				"mode":         cfg.Mode,
				"login_url":    "/api/auth/login",
			},
		})
	}
}

func resolveRequestUser(c *gin.Context, cfg *AuthConfig) *AuthUser {
	// 1. Check signed session cookie (OIDC)
	if cookieVal, err := c.Cookie(sessionCookieName); err == nil && cookieVal != "" {
		if user, err := verifySessionToken(cookieVal, cfg.SessionSecret); err == nil {
			return user
		}
	}

	// 2. Check Trusted Reverse-Proxy Headers (Authelia / Authentik / OAuth2-Proxy)
	if cfg.TrustedHeaderEnabled {
		username := strings.TrimSpace(c.GetHeader(cfg.TrustedUserHeader))
		if username == "" {
			username = strings.TrimSpace(c.GetHeader("X-Forwarded-User"))
		}
		if username != "" {
			name := strings.TrimSpace(c.GetHeader(cfg.TrustedNameHeader))
			if name == "" {
				name = username
			}
			email := strings.TrimSpace(c.GetHeader(cfg.TrustedEmailHeader))
			if email == "" {
				email = strings.TrimSpace(c.GetHeader("X-Forwarded-Email"))
			}
			rawGroups := c.GetHeader(cfg.TrustedGroupsHeader)
			if rawGroups == "" {
				rawGroups = c.GetHeader("X-Forwarded-Groups")
			}
			var groups []string
			for _, g := range strings.Split(rawGroups, ",") {
				if trimmed := strings.TrimSpace(g); trimmed != "" {
					groups = append(groups, trimmed)
				}
			}
			user := &AuthUser{
				Subject:  username,
				Username: username,
				Name:     name,
				Email:    email,
				Groups:   groups,
				Provider: "sso-header",
			}
			if hasAllowedGroup(user.Groups, cfg.OIDCAllowedGroups) {
				return user
			}
		}
	}

	return nil
}

func hasAllowedGroup(userGroups, allowedGroups []string) bool {
	if len(allowedGroups) == 0 {
		return true
	}
	set := make(map[string]bool, len(userGroups))
	for _, g := range userGroups {
		set[strings.ToLower(strings.TrimSpace(g))] = true
	}
	for _, req := range allowedGroups {
		if set[strings.ToLower(strings.TrimSpace(req))] {
			return true
		}
	}
	return false
}

// RegisterAuthRoutes registers `/api/auth/status`, `/api/auth/login`, `/api/auth/callback`, and `/api/auth/logout`.
func RegisterAuthRoutes(router *gin.RouterGroup, cfg *AuthConfig) {
	auth := router.Group("/auth")
	{
		auth.GET("/status", func(c *gin.Context) {
			var user *AuthUser
			if val, exists := c.Get(authUserContextKey); exists {
				user, _ = val.(*AuthUser)
			}
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data: gin.H{
					"enabled":       cfg.Enabled,
					"mode":          cfg.Mode,
					"authenticated": user != nil,
					"user":          user,
					"login_url":     "/api/auth/login",
				},
			})
		})

		auth.GET("/login", func(c *gin.Context) {
			if cfg.OIDCIssuerURL == "" || cfg.OIDCClientID == "" {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "OIDC is not configured (set OIDC_ISSUER_URL and OIDC_CLIENT_ID)",
				})
				return
			}
			doc, err := fetchOIDCDiscovery(cfg.OIDCIssuerURL)
			if err != nil {
				c.JSON(http.StatusBadGateway, models.Response{
					Success: false,
					Error:   "OIDC discovery failed: " + err.Error(),
				})
				return
			}

			state := randomHex(16)
			verifier := randomHex(32)
			challenge := pkceChallenge(verifier)

			statePayload := state + ":" + verifier
			signedState := signString(statePayload, cfg.SessionSecret)
			c.SetCookie(stateCookieName, signedState, 600, "/", "", isSecureRequest(c), true)

			redirectURI := cfg.OIDCRedirectURL
			if redirectURI == "" {
				scheme := "http"
				if isSecureRequest(c) {
					scheme = "https"
				}
				redirectURI = fmt.Sprintf("%s://%s/api/auth/callback", scheme, c.Request.Host)
			}

			params := url.Values{}
			params.Set("response_type", "code")
			params.Set("client_id", cfg.OIDCClientID)
			params.Set("redirect_uri", redirectURI)
			params.Set("scope", cfg.OIDCScopes)
			params.Set("state", state)
			params.Set("code_challenge", challenge)
			params.Set("code_challenge_method", "S256")

			c.Redirect(http.StatusFound, doc.AuthorizationEndpoint+"?"+params.Encode())
		})

		auth.GET("/callback", func(c *gin.Context) {
			code := strings.TrimSpace(c.Query("code"))
			state := strings.TrimSpace(c.Query("state"))
			if code == "" || state == "" {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Missing OIDC code or state",
				})
				return
			}

			stateCookie, err := c.Cookie(stateCookieName)
			if err != nil {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Missing OIDC state cookie",
				})
				return
			}
			c.SetCookie(stateCookieName, "", -1, "/", "", isSecureRequest(c), true)

			rawStatePayload, ok := verifySignedString(stateCookie, cfg.SessionSecret)
			if !ok {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Invalid OIDC state signature",
				})
				return
			}
			parts := strings.SplitN(rawStatePayload, ":", 2)
			if len(parts) != 2 || parts[0] != state {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "OIDC state mismatch",
				})
				return
			}
			verifier := parts[1]

			doc, err := fetchOIDCDiscovery(cfg.OIDCIssuerURL)
			if err != nil {
				c.JSON(http.StatusBadGateway, models.Response{
					Success: false,
					Error:   "OIDC discovery failed: " + err.Error(),
				})
				return
			}

			redirectURI := cfg.OIDCRedirectURL
			if redirectURI == "" {
				scheme := "http"
				if isSecureRequest(c) {
					scheme = "https"
				}
				redirectURI = fmt.Sprintf("%s://%s/api/auth/callback", scheme, c.Request.Host)
			}

			user, err := exchangeOIDCCode(doc, cfg, code, redirectURI, verifier)
			if err != nil {
				c.JSON(http.StatusUnauthorized, models.Response{
					Success: false,
					Error:   "OIDC token exchange failed: " + err.Error(),
				})
				return
			}

			if !hasAllowedGroup(user.Groups, cfg.OIDCAllowedGroups) {
				c.JSON(http.StatusForbidden, models.Response{
					Success: false,
					Error:   "User does not belong to an authorized OIDC group",
				})
				return
			}

			token, err := issueSessionToken(user, cfg.SessionSecret, 12*time.Hour)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   "Failed to issue session token",
				})
				return
			}

			c.SetCookie(sessionCookieName, token, int((12 * time.Hour).Seconds()), "/", "", isSecureRequest(c), true)
			c.Redirect(http.StatusFound, "/")
		})

		auth.POST("/logout", func(c *gin.Context) {
			c.SetCookie(sessionCookieName, "", -1, "/", "", isSecureRequest(c), true)
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: "Logged out",
			})
		})
	}
}

func fetchOIDCDiscovery(issuer string) (*oidcDiscoveryDoc, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	discoveryMu.RLock()
	if cached, ok := discoveryCache[issuer]; ok {
		discoveryMu.RUnlock()
		return cached, nil
	}
	discoveryMu.RUnlock()

	wellKnown := issuer + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("discovery HTTP %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("incomplete OIDC discovery document")
	}

	discoveryMu.Lock()
	discoveryCache[issuer] = &doc
	discoveryMu.Unlock()
	return &doc, nil
}

func exchangeOIDCCode(doc *oidcDiscoveryDoc, cfg *AuthConfig, code, redirectURI, verifier string) (*AuthUser, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", cfg.OIDCClientID)
	if cfg.OIDCClientSecret != "" {
		form.Set("client_secret", cfg.OIDCClientSecret)
	}
	form.Set("code_verifier", verifier)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&tokenResp); err != nil {
		return nil, err
	}

	claims := make(map[string]interface{})
	if tokenResp.IDToken != "" {
		_ = decodeJWTClaims(tokenResp.IDToken, claims)
	}

	if doc.UserinfoEndpoint != "" && tokenResp.AccessToken != "" {
		uReq, err := http.NewRequest(http.MethodGet, doc.UserinfoEndpoint, nil)
		if err == nil {
			uReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
			if uResp, err := client.Do(uReq); err == nil {
				defer uResp.Body.Close()
				if uResp.StatusCode < 300 {
					_ = json.NewDecoder(io.LimitReader(uResp.Body, 1024*1024)).Decode(&claims)
				}
			}
		}
	}

	sub, _ := claims["sub"].(string)
	username, _ := claims["preferred_username"].(string)
	name, _ := claims["name"].(string)
	email, _ := claims["email"].(string)
	if username == "" {
		username = email
	}
	if username == "" {
		username = sub
	}
	if name == "" {
		name = username
	}

	var groups []string
	if rawGroups, ok := claims["groups"].([]interface{}); ok {
		for _, g := range rawGroups {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
	}

	return &AuthUser{
		Subject:  sub,
		Username: username,
		Name:     name,
		Email:    email,
		Groups:   groups,
		Provider: "oidc",
	}, nil
}

func decodeJWTClaims(jwtStr string, out map[string]interface{}) error {
	parts := strings.Split(jwtStr, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, &out)
}

func issueSessionToken(user *AuthUser, secret []byte, ttl time.Duration) (string, error) {
	u := *user
	u.Expires = time.Now().Add(ttl).Unix()
	raw, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	return signString(b64, secret), nil
}

func verifySessionToken(token string, secret []byte) (*AuthUser, error) {
	b64, ok := verifySignedString(token, secret)
	if !ok {
		return nil, fmt.Errorf("invalid token signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	var user AuthUser
	if err := json.Unmarshal(raw, &user); err != nil {
		return nil, err
	}
	if user.Expires > 0 && time.Now().Unix() > user.Expires {
		return nil, fmt.Errorf("session expired")
	}
	return &user, nil
}

func signString(payload string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func verifySignedString(signed string, secret []byte) (string, bool) {
	idx := strings.LastIndex(signed, ".")
	if idx <= 0 {
		return "", false
	}
	payload := signed[:idx]
	sig := signed[idx+1:]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}
	return payload, true
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

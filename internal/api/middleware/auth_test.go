package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestSessionTokenIssueAndVerify(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	user := &AuthUser{
		Subject:  "user-1",
		Username: "shinobi",
		Name:     "JustShinobi",
		Email:    "shinobi@kyo.ninja",
		Groups:   []string{"admins", "secops"},
		Provider: "oidc",
	}

	token, err := issueSessionToken(user, secret, 1*time.Hour)
	if err != nil {
		t.Fatalf("issueSessionToken failed: %v", err)
	}

	verified, err := verifySessionToken(token, secret)
	if err != nil {
		t.Fatalf("verifySessionToken failed: %v", err)
	}
	if verified.Username != "shinobi" || len(verified.Groups) != 2 {
		t.Fatalf("unexpected verified user: %+v", verified)
	}

	// Tampered signature must fail
	if _, err := verifySessionToken(token+"tamper", secret); err == nil {
		t.Fatalf("expected tampered token to fail verification")
	}
}

func TestTrustedHeaderSSOAndOIDCAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_TRUSTED_HEADER_ENABLED", "true")
	t.Setenv("OIDC_ALLOWED_GROUPS", "admins")

	cfg := LoadAuthConfig()
	r := gin.New()
	api := r.Group("/api")
	api.Use(AuthMiddleware(cfg))
	RegisterAuthRoutes(api, cfg)
	api.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// 1. Unauthenticated request to /api/protected -> 401
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/protected", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", w.Code)
	}

	// 2. Trusted header with non-allowed group -> 401
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Remote-User", "guest")
	req.Header.Set("Remote-Groups", "viewers")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized group, got %d", w.Code)
	}

	// 3. Trusted header with allowed group -> 200
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Remote-User", "shinobi")
	req.Header.Set("Remote-Name", "JustShinobi")
	req.Header.Set("Remote-Email", "shinobi@kyo.ninja")
	req.Header.Set("Remote-Groups", "users,admins")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorized SSO header, got %d body=%s", w.Code, w.Body.String())
	}

	// 4. Check /api/auth/status reflects authenticated user
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.Header.Set("Remote-User", "shinobi")
	req.Header.Set("Remote-Groups", "admins")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/auth/status, got %d", w.Code)
	}
}

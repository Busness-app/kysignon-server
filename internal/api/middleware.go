package api

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
)

type contextKey string

const (
	userContextKey    contextKey = "user"
	sessionContextKey contextKey = "session"
)

type MiddlewareManager struct {
	store             *store.Store
	trustedCIDRs      []*net.IPNet
	rateLimiters      map[string]*RateLimiter
	rateLimitersMutex sync.RWMutex
}

type RateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func NewMiddlewareManager(s *store.Store, trustedCIDRs []string) *MiddlewareManager {
	var parsedCIDRs []*net.IPNet
	for _, cidr := range trustedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedCIDRs = append(parsedCIDRs, ipNet)
		}
	}

	return &MiddlewareManager{
		store:        s,
		trustedCIDRs: parsedCIDRs,
		rateLimiters: make(map[string]*RateLimiter),
	}
}

// ClientIP extracts real client IP respecting trusted proxy CIDRs.
func (m *MiddlewareManager) ClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		return remoteHost
	}

	isTrusted := false
	for _, cidr := range m.trustedCIDRs {
		if cidr.Contains(remoteIP) {
			isTrusted = true
			break
		}
	}

	if !isTrusted {
		return remoteHost
	}

	// Read Cloudflare or XFF headers if upstream is trusted
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	return remoteHost
}

// SecurityHeaders applies security and CSP headers.
func (m *MiddlewareManager) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// Content Security Policy allowing local assets, Google/local fonts, and inline styles for UI
		csp := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
		w.Header().Set("Content-Security-Policy", csp)

		next.ServeHTTP(w, r)
	})
}

// RateLimit limits requests per IP and action bucket.
func (m *MiddlewareManager) RateLimit(bucket string, maxTokens, refillRate float64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := m.ClientIP(r)
			key := bucket + ":" + ip

			m.rateLimitersMutex.Lock()
			limiter, exists := m.rateLimiters[key]
			if !exists {
				limiter = &RateLimiter{
					tokens:     maxTokens,
					maxTokens:  maxTokens,
					refillRate: refillRate,
					lastRefill: time.Now(),
				}
				m.rateLimiters[key] = limiter
			}
			m.rateLimitersMutex.Unlock()

			limiter.mu.Lock()
			now := time.Now()
			elapsed := now.Sub(limiter.lastRefill).Seconds()
			limiter.tokens += elapsed * limiter.refillRate
			if limiter.tokens > limiter.maxTokens {
				limiter.tokens = limiter.maxTokens
			}
			limiter.lastRefill = now

			if limiter.tokens < 1.0 {
				limiter.mu.Unlock()
				http.Error(w, `{"error":"rate_limit_exceeded","error_description":"Too many requests"}`, http.StatusTooManyRequests)
				return
			}

			limiter.tokens -= 1.0
			limiter.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth authenticates request via session cookie or Bearer token.
func (m *MiddlewareManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("kysignon_session")
		if err != nil || cookie.Value == "" {
			http.Error(w, `{"error":"unauthorized","error_description":"Authentication required"}`, http.StatusUnauthorized)
			return
		}

		tokenHash := crypto.HashSHA256(cookie.Value)
		sess, err := m.store.GetSessionByTokenHash(tokenHash)
		if err != nil || sess == nil {
			http.Error(w, `{"error":"unauthorized","error_description":"Invalid session"}`, http.StatusUnauthorized)
			return
		}

		if time.Now().UTC().After(sess.ExpiresAt) {
			_ = m.store.DeleteSession(sess.ID)
			http.Error(w, `{"error":"unauthorized","error_description":"Session expired"}`, http.StatusUnauthorized)
			return
		}

		user, err := m.store.GetUserByID(sess.UserID)
		if err != nil || user == nil || user.Status != "active" {
			http.Error(w, `{"error":"unauthorized","error_description":"User inactive or not found"}`, http.StatusUnauthorized)
			return
		}

		// Touch session last active
		_ = m.store.TouchSession(sess.ID)

		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin ensures authenticated user has admin role.
func (m *MiddlewareManager) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(userContextKey).(*store.User)
		if !ok || user == nil || user.Role != "admin" {
			http.Error(w, `{"error":"forbidden","error_description":"Administrator access required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CSRFValidate enforces double-submit CSRF protection for non-GET/HEAD/OPTIONS methods.
func (m *MiddlewareManager) CSRFValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Bypass CSRF for public native push response, system registration, and OAuth token endpoints
		path := r.URL.Path
		if path == "/api/systems/register" ||
			path == "/api/notifications/native/register" ||
			path == "/api/mfa/push/respond" ||
			path == "/oauth/token" ||
			path == "/oauth/revoke" {
			next.ServeHTTP(w, r)
			return
		}

		csrfCookie, err := r.Cookie("kysignon_csrf")
		if err != nil || csrfCookie.Value == "" {
			http.Error(w, `{"error":"invalid_csrf","error_description":"CSRF cookie missing"}`, http.StatusForbidden)
			return
		}

		csrfHeader := r.Header.Get("X-CSRF-Token")
		if csrfHeader == "" {
			csrfHeader = r.FormValue("csrf_token")
		}

		if subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfHeader)) != 1 {
			http.Error(w, `{"error":"invalid_csrf","error_description":"CSRF token mismatch"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext retrieves authenticated user from context.
func GetUserFromContext(ctx context.Context) *store.User {
	if u, ok := ctx.Value(userContextKey).(*store.User); ok {
		return u
	}
	return nil
}

// GetSessionFromContext retrieves active session from context.
func GetSessionFromContext(ctx context.Context) *store.Session {
	if s, ok := ctx.Value(sessionContextKey).(*store.Session); ok {
		return s
	}
	return nil
}

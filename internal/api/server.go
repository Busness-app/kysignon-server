package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yoshiofthewire/kysignon-server/internal/audit"
	"github.com/Yoshiofthewire/kysignon-server/internal/config"
	"github.com/Yoshiofthewire/kysignon-server/internal/crypto"
	"github.com/Yoshiofthewire/kysignon-server/internal/mfa"
	"github.com/Yoshiofthewire/kysignon-server/internal/oauth"
	"github.com/Yoshiofthewire/kysignon-server/internal/store"
	"github.com/Yoshiofthewire/kysignon-server/internal/sync"
)

type Server struct {
	cfg         *config.Config
	store       *store.Store
	keyManager  *crypto.JWTKeyManager
	syncEngine  *sync.Engine
	mfaEngine   *mfa.Engine
	oauthEngine *oauth.Engine
	audit       *audit.Logger
	middleware  *MiddlewareManager
	httpServer  *http.Server
	staticFS    fs.FS
}

func NewServer(
	cfg *config.Config,
	s *store.Store,
	km *crypto.JWTKeyManager,
	syncEngine *sync.Engine,
	mfaEngine *mfa.Engine,
	oauthEngine *oauth.Engine,
	auditLogger *audit.Logger,
	staticFS fs.FS,
) *Server {
	mm := NewMiddlewareManager(s, cfg.TrustedProxyCIDRs)

	srv := &Server{
		cfg:         cfg,
		store:       s,
		keyManager:  km,
		syncEngine:  syncEngine,
		mfaEngine:   mfaEngine,
		oauthEngine: oauthEngine,
		audit:       auditLogger,
		middleware:  mm,
		staticFS:    staticFS,
	}

	mux := srv.routes()

	// Wrap entire mux with security headers and CSRF validation
	handler := mm.SecurityHeaders(mm.CSRFValidate(mux))

	srv.httpServer = &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}

	return srv
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	authH := NewAuthHandler(s.store, s.mfaEngine, s.audit, s.middleware)
	devH := NewDeviceHandler(s.store, s.mfaEngine, s.audit, s.middleware, s.cfg.IssuerURL)
	adminH := NewAdminHandler(s.store, s.syncEngine, s.audit, s.middleware, s.cfg.IssuerURL)
	oauthH := NewOAuthHandler(s.store, s.oauthEngine, s.audit, s.middleware)

	// Health Check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// OIDC Discovery & JWKS
	mux.HandleFunc("GET /.well-known/openid-configuration", oauthH.OIDCConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", oauthH.JWKS)

	// Auth Endpoints
	mux.HandleFunc("GET /api/auth/csrf", authH.GetCSRFToken)
	mux.Handle("POST /api/auth/login", s.middleware.RateLimit("login", 10, 0.2)(http.HandlerFunc(authH.Login)))
	mux.Handle("POST /api/auth/mfa/totp/verify", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(authH.VerifyTOTP)))
	mux.Handle("POST /api/auth/mfa/recovery/verify", s.middleware.RateLimit("mfa", 5, 0.1)(http.HandlerFunc(authH.VerifyRecoveryCode)))
	mux.HandleFunc("POST /api/auth/mfa/push/poll", authH.PollPushChallenge)
	mux.HandleFunc("POST /api/auth/mfa/push/finish", authH.FinishPushLogin)
	mux.Handle("POST /api/mfa/push/respond", s.middleware.RateLimit("push_respond", 15, 0.5)(http.HandlerFunc(authH.RespondPush)))
	mux.HandleFunc("GET /api/notifications/native/pull", authH.PullNotifications)

	// System Pairing Redemption (Unauthenticated with 90s token)
	mux.Handle("POST /api/systems/register", s.middleware.RateLimit("system_reg", 10, 0.2)(http.HandlerFunc(adminH.RegisterPairedSystem)))

	// Native Device Pairing Registration (Unauthenticated with 90s PIN/token)
	mux.Handle("POST /api/notifications/native/register", s.middleware.RateLimit("device_reg", 10, 0.2)(http.HandlerFunc(devH.RegisterNativeDevice)))

	// Authenticated User Routes
	authM := s.middleware.RequireAuth
	mux.Handle("POST /api/auth/logout", authM(http.HandlerFunc(authH.Logout)))
	mux.Handle("GET /api/auth/me", authM(http.HandlerFunc(authH.Me)))

	mux.Handle("POST /api/user/devices/pairing-token", authM(http.HandlerFunc(devH.GenerateDevicePairingToken)))
	mux.Handle("GET /api/user/devices", authM(http.HandlerFunc(devH.ListUserDevices)))
	mux.Handle("DELETE /api/user/devices/{id}", authM(http.HandlerFunc(devH.DeleteUserDevice)))
	mux.Handle("PUT /api/notifications/native/devices/{id}/mfa", authM(http.HandlerFunc(devH.SetDeviceMFAApprover)))

	mux.Handle("POST /api/user/mfa/totp/setup", authM(http.HandlerFunc(devH.SetupTOTP)))
	mux.Handle("POST /api/user/mfa/totp/enable", authM(http.HandlerFunc(devH.EnableTOTP)))
	mux.Handle("POST /api/user/recovery-codes", authM(http.HandlerFunc(devH.GenerateRecoveryCodes)))
	mux.Handle("GET /api/user/applications", authM(http.HandlerFunc(devH.ListApplications)))

	// OAuth & OIDC
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		// If session cookie exists, authenticate context; otherwise proceed unauthenticated
		if cookie, err := r.Cookie("kysignon_session"); err == nil && cookie.Value != "" {
			tokenHash := crypto.HashSHA256(cookie.Value)
			if sess, _ := s.store.GetSessionByTokenHash(tokenHash); sess != nil {
				if user, _ := s.store.GetUserByID(sess.UserID); user != nil && user.Status == "active" {
					ctx := context.WithValue(r.Context(), userContextKey, user)
					oauthH.Authorize(w, r.WithContext(ctx))
					return
				}
			}
		}
		oauthH.Authorize(w, r)
	})
	mux.Handle("POST /oauth/token", s.middleware.RateLimit("oauth_token", 30, 1.0)(http.HandlerFunc(oauthH.Token)))
	mux.HandleFunc("GET /oauth/userinfo", oauthH.Userinfo)
	mux.HandleFunc("POST /oauth/revoke", oauthH.Revoke)

	// Admin Routes (Auth + Admin check)
	adminM := func(h http.Handler) http.Handler {
		return authM(s.middleware.RequireAdmin(h))
	}

	mux.Handle("GET /api/admin/users", adminM(http.HandlerFunc(adminH.ListUsers)))
	mux.Handle("POST /api/admin/users", adminM(http.HandlerFunc(adminH.CreateUser)))
	mux.Handle("PUT /api/admin/users/{id}", adminM(http.HandlerFunc(adminH.UpdateUser)))
	mux.Handle("POST /api/admin/users/{id}/reset-mfa", adminM(http.HandlerFunc(adminH.ResetUserMFA)))
	mux.Handle("POST /api/admin/users/{id}/revoke-sessions", adminM(http.HandlerFunc(adminH.RevokeUserSessions)))
	mux.Handle("DELETE /api/admin/users/{id}", adminM(http.HandlerFunc(adminH.DeleteUser)))

	mux.Handle("POST /api/admin/systems/pairing-token", adminM(http.HandlerFunc(adminH.GenerateSystemPairingToken)))
	mux.Handle("GET /api/admin/systems", adminM(http.HandlerFunc(adminH.ListPairedSystems)))
	mux.Handle("POST /api/admin/systems/{id}/resync", adminM(http.HandlerFunc(adminH.ResyncSystem)))
	mux.Handle("DELETE /api/admin/systems/{id}", adminM(http.HandlerFunc(adminH.DeletePairedSystem)))

	mux.Handle("GET /api/admin/clients", adminM(http.HandlerFunc(adminH.ListOAuthClients)))
	mux.Handle("POST /api/admin/clients", adminM(http.HandlerFunc(adminH.CreateOAuthClient)))
	mux.Handle("DELETE /api/admin/clients/{id}", adminM(http.HandlerFunc(adminH.DeleteOAuthClient)))

	mux.Handle("GET /api/admin/applications", adminM(http.HandlerFunc(adminH.CreateApplication)))
	mux.Handle("DELETE /api/admin/applications/{id}", adminM(http.HandlerFunc(adminH.DeleteApplication)))

	mux.Handle("GET /api/admin/audit-events", adminM(http.HandlerFunc(adminH.ListAuditEvents)))

	// Static CSS & Fonts from filesystem if present
	cssDir := http.Dir("./css")
	mux.Handle("GET /css/", http.StripPrefix("/css/", http.FileServer(cssDir)))

	fontsDir := http.Dir("./fonts")
	mux.Handle("GET /fonts/", http.StripPrefix("/fonts/", http.FileServer(fontsDir)))

	// Explicit Favicon routes
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if s.staticFS != nil {
			if data, err := fs.ReadFile(s.staticFS, "favicon.svg"); err == nil {
				_, _ = w.Write(data)
				return
			}
		}
		if data, err := os.ReadFile("web/dist/favicon.svg"); err == nil {
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(defaultFaviconSVG))
	})

	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if s.staticFS != nil {
			if data, err := fs.ReadFile(s.staticFS, "favicon.ico"); err == nil {
				_, _ = w.Write(data)
				return
			}
			if data, err := fs.ReadFile(s.staticFS, "favicon.svg"); err == nil {
				_, _ = w.Write(data)
				return
			}
		}
		if data, err := os.ReadFile("web/dist/favicon.ico"); err == nil {
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(defaultFaviconSVG))
	})

	// Static Frontend SPA fallback handler
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Check if requesting static asset file directly
		if s.staticFS != nil {
			f, err := s.staticFS.Open(strings.TrimPrefix(path, "/"))
			if err == nil {
				_ = f.Close()
				http.FileServer(http.FS(s.staticFS)).ServeHTTP(w, r)
				return
			}

			// SPA Fallback to index.html
			indexData, err := fs.ReadFile(s.staticFS, "index.html")
			if err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(indexData)
				return
			}
		}

		// Fallback to local web/dist or minimal placeholder
		if data, err := os.ReadFile(filepath.Join("web", "dist", "index.html")); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}

		// Serve minimal SPA bootstrap
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(defaultIndexHTML))
	})

	return mux
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

const defaultIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KySignOn — Identity & SSO</title>
    <link rel="stylesheet" href="/css/styles.css">
    <style>
        body { margin: 0; background: #0d0f14; color: #e2e8f0; font-family: 'Space Grotesk', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #161a22; border: 1px solid rgba(77, 238, 234, 0.2); border-radius: 8px; padding: 2rem; max-width: 480px; width: 90%; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
        h1 { font-family: 'Space Grotesk', sans-serif; color: #4deeea; font-size: 1.5rem; margin-top: 0; }
        p { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }
        .badge { font-family: 'IBM Plex Mono', monospace; background: rgba(77, 238, 234, 0.1); color: #4deeea; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div id="root">
        <div class="card">
            <h1>KySignOn Server</h1>
            <p>Single-Organization Identity & Account Replication Service.</p>
            <p><span class="badge">API READY</span> • Check <code>/healthz</code> or <code>/.well-known/openid-configuration</code>.</p>
        </div>
    </div>
</body>
</html>`

const defaultFaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <rect width="64" height="64" rx="14" fill="#0d0f14"/>
  <rect x="1" y="1" width="62" height="62" rx="13" stroke="#4deeea" stroke-opacity="0.3" stroke-width="1.5"/>
  <path d="M32 10 L48 16 V30 C48 41.5 41.2 50.2 32 54 C22.8 50.2 16 41.5 16 30 V16 L32 10 Z" fill="#121820" stroke="#4deeea" stroke-width="2.5" stroke-linejoin="round"/>
  <circle cx="32" cy="27" r="5.5" fill="#0d0f14" stroke="#4deeea" stroke-width="2"/>
  <path d="M32 32.5 V42 M29 42 H35" stroke="#4deeea" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="32" cy="27" r="2" fill="#4deeea"/>
</svg>`

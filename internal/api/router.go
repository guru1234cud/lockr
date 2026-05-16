package api

import (
	"net/http"
)

func (s *Server) routes() http.Handler {
	authed := http.NewServeMux()

	// Auth management.
	authed.HandleFunc("/v1/auth/session", s.handleLogout)
	authed.HandleFunc("/v1/auth/whoami", s.handleWhoAmI)

	// KV secrets.
	authed.HandleFunc("/v1/secrets/kv/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case hasSuffix(path, "/rollback") && r.Method == http.MethodPost:
			s.handleKVRollback(w, r)
		default:
			switch r.Method {
			case http.MethodGet:
				s.handleKVGet(w, r)
			case http.MethodPut:
				s.handleKVPut(w, r)
			case http.MethodDelete:
				s.handleKVDelete(w, r)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
		}
	})

	// Transit encryption.
	authed.HandleFunc("/v1/secrets/transit/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case hasSuffix(path, "/create"):
			s.withAdmin(s.handleTransitCreate)(w, r)
		case hasSuffix(path, "/encrypt"):
			s.handleTransitEncrypt(w, r)
		case hasSuffix(path, "/decrypt"):
			s.handleTransitDecrypt(w, r)
		case hasSuffix(path, "/rotate"):
			s.handleTransitRotate(w, r)
		case hasSuffix(path, "/info"):
			s.handleTransitInfo(w, r)
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	})

	// System / admin routes.
	authed.HandleFunc("/v1/sys/status", s.withAdmin(s.handleStatus))
	authed.HandleFunc("/v1/sys/enroll", s.withAdmin(s.handleEnroll))
	authed.HandleFunc("/v1/sys/revoke/", s.withAdmin(s.handleRevoke))
	authed.HandleFunc("/v1/sys/audit", s.withAdmin(s.handleAudit))
	authed.HandleFunc("/v1/sys/admin/create", s.withAdmin(s.handleAdminCreate))
	authed.HandleFunc("/v1/sys/admin/", s.withAdmin(s.handleAdminDelete))
	authed.HandleFunc("/v1/sys/policy/reload", s.withAdmin(s.handlePolicyReload))

	// User management (admin only).
	authed.HandleFunc("/v1/sys/users", s.withAdmin(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			s.handleUserCreate(w, r)
		case http.MethodGet:
			s.handleUserList(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))
	authed.HandleFunc("/v1/sys/users/", s.withAdmin(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			s.handleUserDelete(w, r)
		case http.MethodPut:
			s.handleUserUpdate(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))

	mux := http.NewServeMux()

	// Unauthenticated routes — registered before the catch-all so they take priority.
	mux.HandleFunc("/v1/sys/health", s.handleHealth)
	mux.HandleFunc("/v1/auth/challenge", s.handleChallenge)
	mux.HandleFunc("/v1/auth/verify", s.handleVerify)
	mux.HandleFunc("/v1/auth/totp", s.handleTOTPLogin)
	mux.HandleFunc("/v1/auth/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/v1/auth/login", s.handleUserLogin)

	// All other /v1/ routes require authentication and are audited.
	mux.Handle("/v1/", s.auditMiddleware(s.authMiddleware(authed)))

	return requestIDMiddleware(mux)
}

func (s *Server) withAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.devMode {
			method, _ := r.Context().Value(ctxAuthMethod).(string)
			if method != "admin_token" {
				writeError(w, http.StatusForbidden, "admin access required")
				return
			}
		}
		h(w, r)
	}
}

func hasSuffix(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}


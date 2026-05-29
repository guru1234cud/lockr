package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/etherance/lockr/internal/audit"
	"github.com/etherance/lockr/internal/auth"
)

type contextKey string

const (
	ctxIdentity   contextKey = "identity"
	ctxAuthMethod contextKey = "auth_method"
	ctxPolicy     contextKey = "policy"
	ctxRequestID  contextKey = "request_id"
	ctxStartTime  contextKey = "start_time"
	ctxAuditState contextKey = "audit_state"
)

// auditState is a mutable holder shared between authMiddleware and auditMiddleware
// via context. authMiddleware writes to it; auditMiddleware reads after the handler
// returns. This is necessary because authMiddleware passes identity to inner handlers
// via r.WithContext, which auditMiddleware (which wraps authMiddleware) cannot observe.
type auditState struct {
	identity   string
	authMethod string
	policy     string
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 12)
		rand.Read(b)
		rid := base64.RawURLEncoding.EncodeToString(b)
		ctx := context.WithValue(r.Context(), ctxRequestID, rid)
		ctx = context.WithValue(ctx, ctxStartTime, time.Now())
		ctx = context.WithValue(ctx, ctxAuditState, &auditState{})
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, _ := r.Context().Value(ctxAuditState).(*auditState)

		setAuditState := func(identity, method, pol string) {
			if state != nil {
				state.identity = identity
				state.authMethod = method
				state.policy = pol
			}
		}

		if s.devMode {
			setAuditState("dev", "dev", "root")
			ctx := context.WithValue(r.Context(), ctxIdentity, "dev")
			ctx = context.WithValue(ctx, ctxAuthMethod, "dev")
			ctx = context.WithValue(ctx, ctxPolicy, "root")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		token := extractToken(r)
		if token == "" {
			if s.allowFirstAdminBootstrap(r) {
				setAuditState("bootstrap", "admin_token", "root")
				ctx := context.WithValue(r.Context(), ctxIdentity, "bootstrap")
				ctx = context.WithValue(ctx, ctxAuthMethod, "admin_token")
				ctx = context.WithValue(ctx, ctxPolicy, "root")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			setAuditState("unauthenticated", "none", "")
			writeError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		// Try session token first.
		if strings.HasPrefix(token, "lvt_") {
			meta, err := s.sessions.Validate(token)
			if err != nil {
				setAuditState("unauthenticated", "session", "")
				writeError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}
			setAuditState(meta.Identity, meta.AuthMethod, meta.Policy)
			ctx := context.WithValue(r.Context(), ctxIdentity, meta.Identity)
			ctx = context.WithValue(ctx, ctxAuthMethod, meta.AuthMethod)
			ctx = context.WithValue(ctx, ctxPolicy, meta.Policy)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Try admin token.
		if strings.HasPrefix(token, "lkat_") {
			rec, err := s.adminAuth.Verify(token)
			if err != nil {
				setAuditState("unauthenticated", "admin_token", "")
				writeError(w, http.StatusUnauthorized, "invalid admin token")
				return
			}
			setAuditState("admin:"+rec.Name, "admin_token", rec.Policy)
			ctx := context.WithValue(r.Context(), ctxIdentity, "admin:"+rec.Name)
			ctx = context.WithValue(ctx, ctxAuthMethod, "admin_token")
			ctx = context.WithValue(ctx, ctxPolicy, rec.Policy)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		setAuditState("unauthenticated", "unknown", "")
		writeError(w, http.StatusUnauthorized, "unrecognized token format")
	})
}

func (s *Server) allowFirstAdminBootstrap(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/sys/admin/create" {
		return false
	}
	hasAdmins, err := s.adminAuth.HasAdmins()
	return err == nil && !hasAdmins
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.devMode {
			next.ServeHTTP(w, r)
			return
		}
		method := r.Context().Value(ctxAuthMethod).(string)
		if method != "admin_token" {
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		if s.auditLog == nil {
			return
		}

		identity := "unauthenticated"
		authMethod := "none"
		policy := ""
		if state, ok := r.Context().Value(ctxAuditState).(*auditState); ok && state.identity != "" {
			identity = state.identity
			authMethod = state.authMethod
			policy = state.policy
		}

		rid, _ := r.Context().Value(ctxRequestID).(string)
		start, _ := r.Context().Value(ctxStartTime).(time.Time)

		status := "allowed"
		if rw.status == http.StatusForbidden || rw.status == http.StatusUnauthorized {
			status = "denied"
		} else if rw.status >= 400 {
			status = "error"
		}

		_ = s.auditLog.Log(audit.Entry{
			Timestamp:  time.Now().UTC(),
			Identity:   identity,
			AuthMethod: authMethod,
			Operation:  semanticOperation(r.Method, r.URL.Path),
			Path:       r.URL.Path,
			Policy:     policy,
			SourceIP:   r.RemoteAddr,
			RequestID:  rid,
			Status:     status,
			DurationMS: time.Since(start).Milliseconds(),
		})
	})
}

func semanticOperation(method, path string) string {
	switch {
	case strings.HasPrefix(path, "/v1/secrets/kv/"):
		if strings.HasSuffix(path, "/rollback") {
			return "kv.rollback"
		}
		switch method {
		case http.MethodGet:
			return "kv.read"
		case http.MethodPut:
			return "kv.write"
		case http.MethodDelete:
			return "kv.delete"
		}
	case strings.HasPrefix(path, "/v1/secrets/transit/"):
		switch {
		case strings.HasSuffix(path, "/encrypt"):
			return "transit.encrypt"
		case strings.HasSuffix(path, "/decrypt"):
			return "transit.decrypt"
		case strings.HasSuffix(path, "/rotate"):
			return "transit.rotate"
		case strings.HasSuffix(path, "/create"):
			return "transit.create"
		case strings.HasSuffix(path, "/info"):
			return "transit.info"
		}
	case path == "/v1/auth/challenge":
		return "auth.challenge"
	case path == "/v1/auth/verify":
		return "auth.verify"
	case path == "/v1/auth/totp":
		return "auth.totp"
	case path == "/v1/auth/admin/login":
		return "auth.admin_login"
	case path == "/v1/auth/login":
		return "auth.user_login"
	case path == "/v1/auth/session":
		return "auth.logout"
	case path == "/v1/auth/whoami":
		return "auth.whoami"
	case strings.HasPrefix(path, "/v1/sys/audit"):
		return "sys.audit"
	case strings.HasPrefix(path, "/v1/sys/enroll"):
		return "sys.enroll"
	case strings.HasPrefix(path, "/v1/sys/revoke/"):
		return "sys.revoke"
	case strings.HasPrefix(path, "/v1/sys/admin/"):
		return "sys.admin"
	case strings.HasPrefix(path, "/v1/sys/users"):
		return "sys.users"
	case strings.HasPrefix(path, "/v1/sys/policy/"):
		return "sys.policy"
	case strings.HasPrefix(path, "/v1/sys/status"):
		return "sys.status"
	}
	return method
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-Lockr-Token")
}

func getIdentity(r *http.Request) string {
	if v, ok := r.Context().Value(ctxIdentity).(string); ok {
		return v
	}
	return ""
}

func getPolicy(r *http.Request) string {
	if v, ok := r.Context().Value(ctxPolicy).(string); ok {
		return v
	}
	return ""
}

func getRequestID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// Unused import guard — auth is used via type assertion above.
var _ = auth.SessionMeta{}

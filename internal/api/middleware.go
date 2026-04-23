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
)

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 12)
		rand.Read(b)
		rid := base64.RawURLEncoding.EncodeToString(b)
		ctx := context.WithValue(r.Context(), ctxRequestID, rid)
		ctx = context.WithValue(ctx, ctxStartTime, time.Now())
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.devMode {
			ctx := context.WithValue(r.Context(), ctxIdentity, "dev")
			ctx = context.WithValue(ctx, ctxAuthMethod, "dev")
			ctx = context.WithValue(ctx, ctxPolicy, "root")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		token := extractToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		// Try session token first.
		if strings.HasPrefix(token, "lvt_") {
			meta, err := s.sessions.Validate(token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}
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
				writeError(w, http.StatusUnauthorized, "invalid admin token")
				return
			}
			ctx := context.WithValue(r.Context(), ctxIdentity, "admin:"+rec.Name)
			ctx = context.WithValue(ctx, ctxAuthMethod, "admin_token")
			ctx = context.WithValue(ctx, ctxPolicy, rec.Policy)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		writeError(w, http.StatusUnauthorized, "unrecognized token format")
	})
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

		identity := "anonymous"
		authMethod := "none"
		if id, ok := r.Context().Value(ctxIdentity).(string); ok {
			identity = id
		}
		if am, ok := r.Context().Value(ctxAuthMethod).(string); ok {
			authMethod = am
		}
		rid, _ := r.Context().Value(ctxRequestID).(string)
		start, _ := r.Context().Value(ctxStartTime).(time.Time)

		status := "allowed"
		if rw.status == http.StatusForbidden || rw.status == http.StatusUnauthorized {
			status = "denied"
		}

		_ = s.auditLog.Log(audit.Entry{
			Timestamp:  time.Now().UTC(),
			Identity:   identity,
			AuthMethod: authMethod,
			Operation:  r.Method,
			Path:       r.URL.Path,
			SourceIP:   r.RemoteAddr,
			RequestID:  rid,
			Status:     status,
			DurationMS: time.Since(start).Milliseconds(),
		})
	})
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

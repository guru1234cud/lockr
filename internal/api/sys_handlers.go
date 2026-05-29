package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/etherance/lockr/internal/audit"
	"github.com/etherance/lockr/internal/auth"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	writeJSON(w, r, http.StatusOK, map[string]any{
		"status":     "running",
		"dev_mode":   s.devMode,
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"alloc_mb":   memStats.Alloc / 1024 / 1024,
		"uptime":     time.Since(s.startTime).String(),
	})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service    string `json:"service"`
		AuthMethod string `json:"auth_method"` // "ed25519" or "totp"
		Policy     string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Service == "" || req.Policy == "" {
		writeError(w, http.StatusBadRequest, "service and policy are required")
		return
	}

	switch req.AuthMethod {
	case "", "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			writeErrorWithReqID(w, r, http.StatusInternalServerError, "key generation failed")
			return
		}
		if err := s.ed25519Auth.RegisterService(auth.ServiceRecord{
			Name:      req.Service,
			PublicKey: pub,
			Policy:    req.Policy,
		}); err != nil {
			writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{
			"service":     req.Service,
			"auth_method": "ed25519",
			"policy":      req.Policy,
			"public_key":  hex.EncodeToString(pub),
			"private_key": hex.EncodeToString(priv),
		})

	case "totp":
		raw, base32Str, err := auth.GenerateSecret()
		if err != nil {
			writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.totpAuth.RegisterTOTP(auth.TOTPRecord{
			Name:   req.Service,
			Secret: raw,
			Policy: req.Policy,
		}); err != nil {
			writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{
			"service":     req.Service,
			"auth_method": "totp",
			"policy":      req.Policy,
			"totp_secret": base32Str,
		})

	default:
		writeError(w, http.StatusBadRequest, "auth_method must be 'ed25519' or 'totp'")
	}
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimPrefix(r.URL.Path, "/v1/sys/revoke/")
	if err := s.ed25519Auth.DeleteService(service); err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	identity := q.Get("identity")
	if identity == "" {
		identity = q.Get("service") // backward-compat alias
	}
	opts := audit.QueryOptions{
		Identity: identity,
		Path:     q.Get("path"),
	}
	if since := q.Get("since"); since != "" {
		// Accept Go duration strings like "24h", "1h30m".
		d, err := time.ParseDuration(since)
		if err == nil {
			opts.Since = d
		}
	}
	if limit := q.Get("limit"); limit != "" {
		opts.Limit, _ = strconv.Atoi(limit)
	}

	entries, err := s.auditLog.Query(opts)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"entries": entries,
		"count":   len(entries),
	})
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.Policy == "" {
		req.Policy = "admin"
	}
	token, err := s.adminAuth.Create(req.Name, req.Policy)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{
		"name":  req.Name,
		"token": token,
	})
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/sys/admin/")
	if err := s.adminAuth.Delete(name); err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if err := s.policy.LoadAll(); err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "reloaded"})
}

// Ensure os is used (for future use).
var _ = os.Getenv

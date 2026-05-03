package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/etherance/lockr/internal/policy"
	"github.com/etherance/lockr/internal/secrets"
)

func (s *Server) handleDBGetConfig(w http.ResponseWriter, r *http.Request) {
	name := dbName(r.URL.Path)
	if !s.policy.Allowed(getPolicy(r), "secrets/db/"+name, policy.CapRead) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}
	cfg, err := s.dbStore.GetConfigSafe(name)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, cfg)
}

func (s *Server) handleDBPutConfig(w http.ResponseWriter, r *http.Request) {
	name := dbName(r.URL.Path)
	if !s.policy.Allowed(getPolicy(r), "secrets/db/"+name, policy.CapWrite) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}
	var cfg secrets.DBConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cfg.Name = name
	if err := s.dbStore.SetConfig(&cfg); err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDBGenCreds(w http.ResponseWriter, r *http.Request) {
	name := dbName(r.URL.Path)
	if !s.policy.Allowed(getPolicy(r), "secrets/db/"+name, policy.CapRead) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}
	lease, err := s.dbStore.GenerateCreds(r.Context(), name)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, lease)
}

func (s *Server) handleDBRevokeLease(w http.ResponseWriter, r *http.Request) {
	// Path: /v1/secrets/db/<name>/creds/<lease_id>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/secrets/db/"), "/")
	if len(parts) < 3 {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	leaseID := parts[2]
	if err := s.dbStore.RevokeLease(r.Context(), leaseID); err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleDBTestConfig(w http.ResponseWriter, r *http.Request) {
	name := dbName(r.URL.Path)
	if err := s.dbStore.TestConnection(r.Context(), name); err != nil {
		writeErrorWithReqID(w, r, http.StatusBadGateway, "connection failed: "+err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok", "message": "connection successful"})
}

func (s *Server) handleDBListLeases(w http.ResponseWriter, r *http.Request) {
	name := dbName(r.URL.Path)
	leases, err := s.dbStore.ListLeases(name)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"leases": leases, "count": len(leases)})
}

func dbName(urlPath string) string {
	path := strings.TrimPrefix(urlPath, "/v1/secrets/db/")
	return strings.SplitN(path, "/", 2)[0]
}

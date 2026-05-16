package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/etherance/lockr/internal/policy"
)

func (s *Server) handleKVGet(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secrets/kv/")

	// Directory listing.
	if strings.HasSuffix(path, "/") {
		if !s.policy.Allowed(getPolicy(r), "secrets/kv/"+path, policy.CapList) {
			writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
			return
		}
		keys, err := s.kvStore.List(path)
		if err != nil {
			writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"keys": keys})
		return
	}

	// Version listing.
	if strings.HasSuffix(path, "/versions") {
		secretPath := strings.TrimSuffix(path, "/versions")
		if !s.policy.Allowed(getPolicy(r), "secrets/kv/"+secretPath, policy.CapRead) {
			writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
			return
		}
		versions, err := s.kvStore.Versions(secretPath)
		if err != nil {
			writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"versions": versions})
		return
	}

	if !s.policy.Allowed(getPolicy(r), "secrets/kv/"+path, policy.CapRead) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}

	version := 0
	if v := r.URL.Query().Get("version"); v != "" {
		var err error
		version, err = strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid version parameter")
			return
		}
	}

	entry, err := s.kvStore.Get(path, version)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, entry)
}

func (s *Server) handleKVPut(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secrets/kv/")

	if !s.policy.Allowed(getPolicy(r), "secrets/kv/"+path, policy.CapWrite) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}

	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	entry, err := s.kvStore.Set(path, body)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	// Never return the value — return metadata only.
	entry.Value = nil
	writeJSON(w, r, http.StatusOK, entry)
}

func (s *Server) handleKVRollback(w http.ResponseWriter, r *http.Request) {
	// Path: /v1/secrets/kv/<path>/rollback
	path := strings.TrimPrefix(r.URL.Path, "/v1/secrets/kv/")
	path = strings.TrimSuffix(path, "/rollback")

	if !s.policy.Allowed(getPolicy(r), "secrets/kv/"+path, policy.CapWrite) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}

	var body struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Version < 1 {
		writeError(w, http.StatusBadRequest, "body must be {\"version\": N} where N >= 1")
		return
	}

	entry, err := s.kvStore.Rollback(path, body.Version)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	entry.Value = nil
	writeJSON(w, r, http.StatusOK, entry)
}

func (s *Server) handleKVDelete(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secrets/kv/")

	if !s.policy.Allowed(getPolicy(r), "secrets/kv/"+path, policy.CapDelete) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}

	if err := s.kvStore.Delete(path); err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

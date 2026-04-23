package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/etherance/lockr/internal/policy"
)

func (s *Server) handleTransitEncrypt(w http.ResponseWriter, r *http.Request) {
	keyname := transitKeyName(r.URL.Path, "/encrypt")
	if !s.policy.Allowed(getPolicy(r), "secrets/transit/"+keyname, policy.CapEncrypt) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}

	var req struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Plaintext == "" {
		writeError(w, http.StatusBadRequest, "plaintext required")
		return
	}

	ct, err := s.transitStore.Encrypt(keyname, []byte(req.Plaintext))
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"ciphertext": ct})
}

func (s *Server) handleTransitDecrypt(w http.ResponseWriter, r *http.Request) {
	keyname := transitKeyName(r.URL.Path, "/decrypt")
	if !s.policy.Allowed(getPolicy(r), "secrets/transit/"+keyname, policy.CapDecrypt) {
		writeErrorWithReqID(w, r, http.StatusForbidden, "permission denied")
		return
	}

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Ciphertext == "" {
		writeError(w, http.StatusBadRequest, "ciphertext required")
		return
	}

	pt, err := s.transitStore.Decrypt(keyname, req.Ciphertext)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusBadRequest, "decryption failed: "+err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"plaintext": string(pt)})
}

func (s *Server) handleTransitRotate(w http.ResponseWriter, r *http.Request) {
	keyname := transitKeyName(r.URL.Path, "/rotate")
	if err := s.transitStore.Rotate(keyname); err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "rotated"})
}

func (s *Server) handleTransitInfo(w http.ResponseWriter, r *http.Request) {
	keyname := transitKeyName(r.URL.Path, "/info")
	info, err := s.transitStore.Info(keyname)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, info)
}

func (s *Server) handleTransitCreate(w http.ResponseWriter, r *http.Request) {
	keyname := transitKeyName(r.URL.Path, "/create")
	if err := s.transitStore.CreateKey(keyname); err != nil {
		writeErrorWithReqID(w, r, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "created", "key": keyname})
}

func transitKeyName(urlPath, suffix string) string {
	path := strings.TrimPrefix(urlPath, "/v1/secrets/transit/")
	return strings.TrimSuffix(path, suffix)
}

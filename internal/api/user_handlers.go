package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Policy   string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" || req.Policy == "" {
		writeError(w, http.StatusBadRequest, "username, password and policy are required")
		return
	}
	if err := s.userAuth.Create(req.Username, req.Password, req.Policy); err != nil {
		writeErrorWithReqID(w, r, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{
		"username": req.Username,
		"policy":   req.Policy,
		"status":   "created",
	})
}

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	users, err := s.userAuth.List()
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{
		"users": users,
		"count": len(users),
	})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/v1/sys/users/")
	if err := s.userAuth.Delete(username); err != nil {
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	// handles /v1/sys/users/<name>/policy and /v1/sys/users/<name>/password
	path := strings.TrimPrefix(r.URL.Path, "/v1/sys/users/")

	switch {
	case strings.HasSuffix(path, "/policy"):
		username := strings.TrimSuffix(path, "/policy")
		var req struct {
			Policy string `json:"policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Policy == "" {
			writeError(w, http.StatusBadRequest, "policy is required")
			return
		}
		if err := s.userAuth.ChangePolicy(username, req.Policy); err != nil {
			writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]string{"status": "updated"})

	case strings.HasSuffix(path, "/password"):
		username := strings.TrimSuffix(path, "/password")
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required")
			return
		}
		if err := s.userAuth.ChangePassword(username, req.Password); err != nil {
			writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]string{"status": "updated"})

	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

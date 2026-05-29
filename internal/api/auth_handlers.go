package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Service == "" {
		writeError(w, http.StatusBadRequest, "service name required")
		return
	}

	challenge, err := s.ed25519Auth.GenerateChallenge(req.Service)
	if err != nil {
		s.logAuthAttempt(r, "svc:"+req.Service, "ed25519", "denied")
		writeErrorWithReqID(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.logAuthAttempt(r, "svc:"+req.Service, "ed25519", "challenge_issued")
	writeJSON(w, r, http.StatusOK, map[string]string{
		"challenge": hex.EncodeToString(challenge),
		"service":   req.Service,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	challengeBytes, err := hex.DecodeString(req.Challenge)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid challenge encoding")
		return
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return
	}

	svc, err := s.ed25519Auth.Verify(challengeBytes, sigBytes)
	if err != nil {
		s.logAuthAttempt(r, "svc:unknown", "ed25519", "denied")
		writeErrorWithReqID(w, r, http.StatusUnauthorized, "authentication failed")
		return
	}

	token, err := s.sessions.Issue("svc:"+svc.Name, "ed25519", svc.Policy)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, "could not issue session")
		return
	}
	s.logAuthAttempt(r, "svc:"+svc.Name, "ed25519", "allowed")
	writeJSON(w, r, http.StatusOK, map[string]any{
		"token":      token,
		"identity":   "svc:" + svc.Name,
		"policy":     svc.Policy,
		"expires_in": s.cfg.Session.TTL.Seconds(),
	})
}

func (s *Server) handleTOTPLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service string `json:"service"`
		Code    uint32 `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rec, err := s.totpAuth.Verify(req.Service, req.Code)
	if err != nil {
		s.logAuthAttempt(r, "svc:"+req.Service, "totp", "denied")
		writeErrorWithReqID(w, r, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	token, err := s.sessions.Issue("svc:"+rec.Name, "totp", rec.Policy)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, "could not issue session")
		return
	}
	s.logAuthAttempt(r, "svc:"+rec.Name, "totp", "allowed")
	writeJSON(w, r, http.StatusOK, map[string]any{
		"token":      token,
		"identity":   "svc:" + rec.Name,
		"policy":     rec.Policy,
		"expires_in": s.cfg.Session.TTL.Seconds(),
	})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rec, err := s.adminAuth.Verify(req.Token)
	if err != nil {
		s.logAuthAttempt(r, "admin:unknown", "admin_token", "denied")
		writeErrorWithReqID(w, r, http.StatusUnauthorized, "invalid admin token")
		return
	}

	token, err := s.sessions.Issue("admin:"+rec.Name, "admin_token", rec.Policy)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, "could not issue session")
		return
	}
	s.logAuthAttempt(r, "admin:"+rec.Name, "admin_token", "allowed")
	writeJSON(w, r, http.StatusOK, map[string]any{
		"token":      token,
		"identity":   "admin:" + rec.Name,
		"policy":     rec.Policy,
		"expires_in": s.cfg.Session.TTL.Seconds(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token != "" {
		_ = s.sessions.Revoke(token)
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rec, err := s.userAuth.Verify(req.Username, req.Password)
	if err != nil {
		s.logAuthAttempt(r, "user:"+req.Username, "password", "denied")
		writeErrorWithReqID(w, r, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := s.sessions.Issue("user:"+rec.Username, "password", rec.Policy)
	if err != nil {
		writeErrorWithReqID(w, r, http.StatusInternalServerError, "could not issue session")
		return
	}
	s.logAuthAttempt(r, "user:"+rec.Username, "password", "allowed")
	writeJSON(w, r, http.StatusOK, map[string]any{
		"token":      token,
		"identity":   "user:" + rec.Username,
		"policy":     rec.Policy,
		"expires_in": s.cfg.Session.TTL.Seconds(),
	})
}

func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]any{
		"identity":    getIdentity(r),
		"policy":      getPolicy(r),
		"server_time": time.Now().UTC(),
	})
}

package api

import (
	"encoding/json"
	"net/http"
)

type envelope struct {
	Data      any    `json:"data"`
	Error     any    `json:"error"`
	RequestID string `json:"request_id"`
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{
		Data:      data,
		Error:     nil,
		RequestID: getRequestID(r),
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{
		Data:      nil,
		Error:     msg,
		RequestID: "",
	})
}

func writeErrorWithReqID(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{
		Data:      nil,
		Error:     msg,
		RequestID: getRequestID(r),
	})
}

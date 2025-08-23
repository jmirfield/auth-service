package http

import (
	"encoding/json"
	"net/http"
)

func Json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, status int, msg string) {
	Json(w, status, map[string]string{"error": msg})
}

func InternalServerError(w http.ResponseWriter) {
	Error(w, http.StatusInternalServerError, "something went wrong")
}

func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

func extractToken(authHeader string) string {
	if authHeader == "" {
		return authHeader
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	return authHeader
}

func writeJsonError(w http.ResponseWriter, message string, statusCode int) {
	errorMessage := map[string]string{"error": message}
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorMessage)
}

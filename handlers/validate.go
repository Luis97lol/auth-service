package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/redis"
)

func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	// Read token from Authorization header
	token := extractToken(r.Header.Get("Authorization"))
	if token == "" {
		writeJsonError(w, "Token not provided", http.StatusBadRequest)
		return
	}

	// Validate token against Redis
	userId, err := redis.ValidateToken(token)
	if err != nil {
		println("Error validating token: ", err.Error())
		writeJsonError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Respond with username
	response := map[string]string{"user": userId}
	json.NewEncoder(w).Encode(response)
}

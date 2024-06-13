package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/redis"
)

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Read token from Authorization header
	token := extractToken(r.Header.Get("Authorization"))
	if token == "" {
		writeJsonError(w, "Token not provided", http.StatusBadRequest)
		return
	}

	// Validate token against Redis
	userId, err := redis.ValidateToken(token)
	if err == nil {
		redis.DeleteToken(token, userId)
	}

	// Respond with username
	response := map[string]string{"response": "Session closed successfully"}
	json.NewEncoder(w).Encode(response)
}

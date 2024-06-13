package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/database"
	"github.com/Luis97lol/auth-service/redis"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	authtoken := extractToken(r.Header.Get("Authorization"))
	if authtoken != "" {
		writeJsonError(w, "Token provided", http.StatusBadRequest)
		return
	}

	// Parse request body
	var credentials database.Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		writeJsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	// Validate user credentials against database
	userId, err := database.ValidateUser(credentials.Organization, credentials.Username, credentials.Password)
	if err != nil {
		writeJsonError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if token, err := redis.ValidateUser(userId); err == nil {
		response := map[string]string{"token": token}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate JWT token and save to Redis
	token, err := redis.GenerateToken(userId)
	if err != nil {
		println("Error generating token: ", err.Error())
		writeJsonError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Respond with token
	response := map[string]string{"token": token}
	json.NewEncoder(w).Encode(response)
}

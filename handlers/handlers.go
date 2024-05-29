package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/database"
	"github.com/Luis97lol/auth-service/redis"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	authtoken := r.Header.Get("Authorization")
	if authtoken != "" {
		http.Error(w, "Token provided", http.StatusBadRequest)
		return
	}

	// Parse request body
	var credentials database.Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate user credentials against database
	validUser, err := database.ValidateUser(credentials.Organization, credentials.Username, credentials.Password)
	if err != nil {
		http.Error(w, "Error validating user credentials", http.StatusInternalServerError)
		return
	}
	if !validUser {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token and save to Redis
	token, err := redis.GenerateToken(credentials.Username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Respond with token
	response := map[string]string{"token": token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	authtoken := r.Header.Get("Authorization")
	if authtoken != "" {
		http.Error(w, "Token provided", http.StatusBadRequest)
		return
	}

	// Parse request body
	var credentials database.Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate user credentials against database
	err = database.InsertUser(credentials.Organization, credentials.Username, credentials.Password)
	if err != nil {
		http.Error(w, "Error creating user credentials", http.StatusInternalServerError)
		return
	}

	// Respond with token
	response := map[string]string{"response": "User created successfully"}
	json.NewEncoder(w).Encode(response)
}

func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	// Read token from Authorization header
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Token not provided", http.StatusBadRequest)
		return
	}

	// Validate token against Redis
	username, err := redis.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Respond with username
	response := map[string]string{"username": username}
	json.NewEncoder(w).Encode(response)
}

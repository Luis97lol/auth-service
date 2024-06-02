package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

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

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

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

	// Validate user credentials against database
	userId, err := database.InsertUser(credentials.Organization, credentials.Username, credentials.Password)
	if err != nil {
		writeJsonError(w, "ErrorError creating user credentials", http.StatusInternalServerError)
		return
	}

	// Respond with token
	response := map[string]string{"response": userId}
	json.NewEncoder(w).Encode(response)
}

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

func RenewHandler(w http.ResponseWriter, r *http.Request) {
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

	token, err = redis.RenewToken(token, userId)
	if err != nil {
		println("Error renewing token: ", err.Error())
		writeJsonError(w, "Invalid token", http.StatusConflict)
		return
	}

	// Respond with username
	response := map[string]string{"token": token}
	json.NewEncoder(w).Encode(response)
}

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

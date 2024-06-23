package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/database"
)

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
	response := map[string]string{"uuid": userId}
	json.NewEncoder(w).Encode(response)
}

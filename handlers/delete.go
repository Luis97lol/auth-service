package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/database"
	"github.com/Luis97lol/auth-service/redis"
	"github.com/gorilla/mux"
)

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	oid := vars["oid"]
	userId := vars["userId"]

	admintoken := extractToken(r.Header.Get("Authorization"))
	if admintoken == "" {
		writeJsonError(w, "Token not provided", http.StatusBadRequest)
		return
	}

	// Validate token against Redis
	_, err := redis.ValidateToken(admintoken)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Token not valid"})
		return
	}

	token, err := redis.ValidateUser(userId)
	if err == nil {
		redis.DeleteToken(token, userId)
	}

	database.DeleteUser(oid, userId)

	// Respond with username
	response := map[string]string{"response": "User deleted successfully"}
	json.NewEncoder(w).Encode(response)
}

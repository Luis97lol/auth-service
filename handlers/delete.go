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

	token := extractToken(r.Header.Get("Authorization"))
	// Validate token against Redis
	_, err := redis.ValidateToken(token)
	if err == nil {
		redis.DeleteToken(token, userId)
	}

	database.DeleteUser(oid, userId)

	// Respond with username
	response := map[string]string{"response": "Session closed successfully"}
	json.NewEncoder(w).Encode(response)
}

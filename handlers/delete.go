package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Luis97lol/auth-service/database"
	"github.com/gorilla/mux"
)

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	// Read token from Authorization header
	LogoutHandler(w, r)
	vars := mux.Vars(r)
	oid := vars["oid"]
	userId := vars["userId"]
	database.DeleteUser(oid, userId)

	// Respond with username
	response := map[string]string{"response": "Session closed successfully"}
	json.NewEncoder(w).Encode(response)
}

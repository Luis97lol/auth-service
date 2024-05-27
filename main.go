package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Luis97lol/auth-service/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	r := mux.NewRouter()
	r.HandleFunc("/login", handlers.LoginHandler).Methods("POST")
	r.HandleFunc("/validate", handlers.ValidateHandler).Methods("GET")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server listening on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Luis97lol/auth-service/database"
	"github.com/Luis97lol/auth-service/handlers"
	"github.com/Luis97lol/auth-service/redis"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize Redis client
	redis.InitRedis()

	// Initialize database connection
	db, err := database.InitDB()
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}
	defer db.Close()

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

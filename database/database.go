package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Organization string `json:"org_id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

var db *sql.DB
var connStr string

func init() {
	defer db.Close()
	connStr = fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"))
	if err := open(); err != nil {
		log.Fatalf("Error initializing database connection: %s", err.Error())
	}
}

func open() error {
	var err error
	db, err = sql.Open("postgres", connStr)
	return err
}

func ValidateUser(oid, username, password string) (bool, error) {
	defer db.Close()
	if err := open(); err != nil {
		fmt.Printf("Error initializing database connection: %s", err.Error())
		return false, err
	}

	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE oid=$1, username=$2", oid, username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	// Compare the provided password with the stored hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		// Password does not match
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}

	// Password matches
	return true, nil
}

func InsertUser(oid, username, password string) error {
	defer db.Close()
	if err := open(); err != nil {
		fmt.Errorf("No se pudo establecer conexion con la base de datos")
		return err
	}

	// Encrypt the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Insert the new user into the database
	_, err = db.Exec("INSERT INTO users (oid, username, password) VALUES ($1, $2, $3)", oid, username, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}

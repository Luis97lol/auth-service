package database

import (
	"database/sql"
	"fmt"
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

func open() error {
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"))

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	return nil
}

func closeDB() {
	if db != nil {
		db.Close()
	}
}

func ValidateUser(oid, username, password string) (string, error) {
	if err := open(); err != nil {
		fmt.Printf("Error initializing database connection: %s", err.Error())
		return "", err
	}
	defer closeDB() // Cierra la conexión solo si se abrió correctamente

	var storedPassword string
	var userId string
	err := db.QueryRow("SELECT id, password FROM credentials WHERE oid=$1 AND username=$2", oid, username).Scan(&userId, &storedPassword)
	if err != nil {
		println("Error al consultar usuario: ", err.Error())
		return "", err
	}

	// Compare the provided password with the stored hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		println("Error al comparar hashes: ", err.Error())
		// Password does not match
		return "", err
	}

	// Password matches
	return userId, nil
}

func InsertUser(oid, username, password string) (string, error) {
	if err := open(); err != nil {
		println("No se pudo establecer conexion con la base de datos")
		return "", err
	}
	defer closeDB() // Cierra la conexión solo si se abrió correctamente

	// Encrypt the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// Insert the new user into the database
	var id string
	err = db.QueryRow(
		"INSERT INTO credentials (oid, username, password) VALUES ($1, $2, $3) RETURNING id",
		oid, username, hashedPassword,
	).Scan(&id)
	if err != nil {
		println("Error al insertar usuario: ", err.Error())
		return "", err
	}

	return id, nil
}

func DeleteUser(oid, userId string) error {
	if err := open(); err != nil {
		println("No se pudo establecer conexion con la base de datos")
		return err
	}
	defer closeDB() // Cierra la conexión solo si se abrió correctamente

	_, err := db.Exec("DELETE FROM credentials WHERE oid = $1 AND id = $2", oid, userId)

	return err
}

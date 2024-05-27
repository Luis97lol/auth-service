package auth

import (
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

type User struct {
	Id        string
	Nickname  string
	Thumbnail *string
	SSO       bool
	IsAdmin   []string `json:"empresa"`
}

type Claim struct {
	User User
	jwt.StandardClaims
}

type ResponseToken struct {
	Token string `json:"token"`
}

type SecuredFunc func(http.ResponseWriter, *http.Request, Claim)

package auth

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("./conf/private.rsa")
	if err != nil {
		log.Fatal("No se pudo leer el archivo de llave privada " + err.Error())
	}
	publicBytes, err := ioutil.ReadFile("./conf/public.rsa.pub")
	if err != nil {
		log.Fatal("No se pudo leer el archivo de llave publica")
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("No se pudo parsear el archivo de llave privada")
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("No se pudo parsear el archivo de llave privada")
	}
}

func GenerateJWT(user User) string {
	claims := Claim{User: user, StandardClaims: jwt.StandardClaims{ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("No se pudo firmar el token")
	}
	return result
}

func validateToken(r *http.Request) (*Claim, error) {
	claim := new(Claim)
	_, err := request.ParseFromRequestWithClaims(r, request.OAuth2Extractor, claim, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	return claim, err
}

func JwtVerify(next SecuredFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var header = r.Header.Get("Authorization")

		header = strings.TrimSpace(header)

		if header == "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Missing auth token")
			return
		}

		claim, err := validateToken(r)
		if err != nil {
			switch err.(type) {
			case *jwt.ValidationError:
				vErr := err.(*jwt.ValidationError)
				switch vErr.Errors {
				case jwt.ValidationErrorExpired:
					tm := time.Unix(claim.ExpiresAt, 0)
					now := time.Now()
					if now.After(tm.Add(-5*time.Minute)) && now.Before(tm) {
						w.WriteHeader(http.StatusRequestTimeout)
						fmt.Fprintf(w, "Session about to expire")
						return
					}
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Token not valid")
			return
		}

		next(w, r, *claim)
	}
}

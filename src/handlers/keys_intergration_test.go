package handlers

import (
	"bthreader/auth-server/src/jwks"
	"bthreader/auth-server/src/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

func TestGetPublicKeyFromEndpoint(t *testing.T) {
	godotenv.Load("../../.env")

	// Get the key from the endpoint
	ts := httptest.NewServer(http.HandlerFunc(KeysHandler))

	keySet, err := jwks.GetJwks(ts.URL)

	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	key, err := jwks.GetKeyFromJwks(keySet, "0")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// Check it works as expected by generating and then decoding a token
	tokenString, _ := token.GenerateToken(token.AccessToken, "Jeff")

	tokenObject, err := jwt.ParseWithClaims(
		tokenString,
		&token.MyCustomClaims{Type: "", RegisteredClaims: jwt.RegisteredClaims{}},
		func(*jwt.Token) (interface{}, error) {
			return key, nil
		},
	)

	claims := tokenObject.Claims.(*token.MyCustomClaims)

	if claims.Issuer != "bthreader" {
		t.Log("incorrect issuer")
		t.FailNow()
	}
}

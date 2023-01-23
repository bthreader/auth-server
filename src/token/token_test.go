package token

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

func TestGetPrivateKey(t *testing.T) {
	godotenv.Load("../../.env")
	key, err := getPrivateKey()

	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	if key == nil {
		t.Log("key is nil pointer")
		t.FailNow()
	}
}

func TestGetPublicKey(t *testing.T) {
	publicKey, err := GetPublicKey()

	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if publicKey == nil {
		t.Log("nul public key pointer")
		t.FailNow()
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	tokenString, err := GenerateToken(RefreshToken, "Jeff")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	parser := jwt.NewParser()
	token, err := parser.ParseWithClaims(
		tokenString,
		&MyCustomClaims{"", jwt.RegisteredClaims{}},
		func(*jwt.Token) (interface{}, error) {
			key, err := GetPublicKey()
			if err != nil {
				t.Log(err)
				t.FailNow()
			}

			return key, nil
		},
	)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	claims := token.Claims.(*MyCustomClaims)

	if claims.Issuer != "bthreader" {
		t.Log(claims.Issuer)
		t.Log("issuer not set correctly")
		t.Fail()
	}
	if claims.Type != RefreshToken {
		t.Log(claims.Type)
		t.Log("refresh token status not set correctly")
		t.Fail()
	}
	if claims.Subject != "Jeff" {
		t.Log(claims.Subject)
		t.Log("subject not set correctly")
		t.Fail()
	}
}

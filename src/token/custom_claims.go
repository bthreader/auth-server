package token

import "github.com/golang-jwt/jwt/v4"

type MyCustomClaims struct {
	Type string `json:"type"`
	jwt.RegisteredClaims
}

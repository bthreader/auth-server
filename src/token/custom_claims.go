package token

import "github.com/golang-jwt/jwt/v4"

type MyCustomClaims struct {
	Type TokenType `json:"type"`
	jwt.RegisteredClaims
}

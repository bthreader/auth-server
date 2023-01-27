// Package token provides a set of functions for generating and inspecting JSON Web Tokens.
package token

import (
	"bthreader/auth-server/src/jwks"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func GenerateToken(tokenType TokenType, sub string) (string, error) {
	var expiresAt time.Time
	switch tokenType {
	case RefreshToken:
		expiresAt = time.Now().Add(time.Hour * 24 * 7)
	case AccessToken:
		expiresAt = time.Now().Add(time.Hour)
	}

	claims := MyCustomClaims{
		tokenType,
		jwt.RegisteredClaims{
			Issuer:    "bthreader",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	privateKey, err := getPrivateKey()
	if err != nil {
		return "", err
	}

	token.Header["kid"] = "0"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func GenerateRefreshTokenCookie(sub string) *http.Cookie {
	refreshToken, _ := GenerateToken(RefreshToken, sub)

	refreshTokenCookie := &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   true,
	}

	return refreshTokenCookie
}

func GetSubFromIdToken(rawIdToken string, issuerUri string) (string, error) {
	idToken, err := jwt.ParseWithClaims(
		rawIdToken,
		&MyCustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			kid := token.Header["kid"].(string)
			key, err := jwks.GetIssuerPublicKey(issuerUri, kid)
			if err != nil {
				return nil, err
			}

			return &key, nil
		},
	)
	if err != nil {
		return "", err
	}

	claims := idToken.Claims.(*MyCustomClaims)

	return claims.Subject, err
}

func GetPublicKey() (*rsa.PublicKey, error) {
	publicKeyString := os.Getenv("PUBLIC_KEY")
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyBytes)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyString := os.Getenv("PRIVATE_KEY")
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyString)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

package token

import (
	"bthreader/auth-server/src/jwks"
	"path/filepath"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Generates access or refresh JWT for a given subject `sub`
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

func GetSubFromIdToken(rawIdToken string, issuerUri string) (string, error) {
	idToken, err := jwt.ParseWithClaims(rawIdToken, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"].(string)
		key, err := jwks.GetIssuerPublicKey(issuerUri, kid)
		if err != nil {
			return nil, err
		}

		return key, nil
	})

	claims := idToken.Claims.(*MyCustomClaims)

	return claims.Subject, err
}

func GetPublicKey() (rsa.PublicKey, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return rsa.PublicKey{}, err
	}
	return privateKey.PublicKey, nil
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	privateKeyFile, err := os.ReadFile(filepath.Join(wd, "../../keys/private_key.pem"))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyFile)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func generateToken(expirationTime time.Time, sub string) {
	claims := &jwt.RegisteredClaims{
		Issuer:    "bthreader",
		Subject:   sub,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.SignedString(os.Getenv("PRIVATE_KEY"))
}

func GetSubFromIdToken(rawIdToken string, issuerUri string) (string, error) {
	idToken, err := jwt.Parse(rawIdToken, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"].(string)
		key, err := GetPublicKey(issuerUri, kid)
		if err != nil {
			return nil, err
		}

		return key, nil
	})

	return idToken.Raw, err
}

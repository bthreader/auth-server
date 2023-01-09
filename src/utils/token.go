// Generates access and refresh tokens, also provides a helper function for ID tokens

package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type MyCustomClaims struct {
	Type string `json:"type"`
	jwt.RegisteredClaims
}

func GenerateToken(tokenType TokenType, sub string) {
	var expiresAt time.Time
	switch tokenType {
	case RefreshToken:
		expiresAt = time.Now().Add(time.Hour * 24 * 7)
	case AccessToken:
		expiresAt = time.Now().Add(time.Hour)
	}

	claims := &MyCustomClaims{
		string(tokenType),
		jwt.RegisteredClaims{
			Issuer:    "bthreader",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// privateKey := rsa.PrivateKey{}
	// publicKey :=

	token.SignedString(os.Getenv("PRIVATE_KEY"))
}

// Retreives the subject claim from an ID token
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

package handlers

import (
	"bthreader/auth-server/src/token"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshTokenCookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "No refresh token cookie", http.StatusBadRequest)
		return
	}

	// Check if it exists in the database
	// If not raise and return

	refreshToken, err := jwt.ParseWithClaims(
		refreshTokenCookie.Value,
		&token.MyCustomClaims{},
		func(jwt *jwt.Token) (interface{}, error) {
			publicKey, _ := token.GetPublicKey()
			return publicKey, nil
		},
	)

	claims := refreshToken.Claims.(*token.MyCustomClaims)
	sub := claims.Subject

	if err != nil {
		// Exists in database but has expired
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		return
	}

	accessToken, _ := token.GenerateToken(token.AccessToken, sub)
	v, _ := json.Marshal(token.TokenResponseBody{AccessToken: accessToken})
	w.Write(v)
}

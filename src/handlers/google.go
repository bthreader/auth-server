package handlers

import (
	"bthreader/auth-server/src/token"
	"encoding/json"
	"io"
	"net/http"
)

func GoogleHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	body := GoogleValidationResponse{}
	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	// Verify the ID token
	sub, err := token.GetSubFromIdToken(body.Credential, "https://accounts.google.com")
	if err != nil {
		http.Error(w, "Unable to verify ID token", http.StatusBadRequest)
		return
	}

	// Issue tokens
	refreshTokenCookie := token.GenerateRefreshTokenCookie(sub)
	http.SetCookie(w, refreshTokenCookie)

	accessToken, _ := token.GenerateToken(token.AccessToken, sub)
	v, _ := json.Marshal(token.TokenResponseBody{AccessToken: accessToken})
	w.Write(v)
}

package handlers

import (
	"bthreader/auth-server/src/token"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
)

// Handles the authorization POST request
// https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
func AppleHandler(w http.ResponseWriter, r *http.Request) {
	// Get the auth code from the request
	var authCode string = r.FormValue("code")

	// Make the verification request
	body, err := getAppleVerificationResponseBody(authCode)

	if err != nil {
		http.Error(w, "Apple verification request failed", 400)
		return
	}

	idToken, err := getIdTokenFromAppleResponseBody(body)

	if err != nil {
		http.Error(w, "Malformed apple verification response", 400)
		return
	}

	sub, err := token.GetSubFromIdToken(idToken, "https://appleid.apple.com/")

	refreshToken, _ := token.GenerateToken(token.RefreshToken, sub)
	accessToken, _ := token.GenerateToken(token.AccessToken, sub)

	// Refresh token in a cookie, access token in body
	refreshTokenCookie := &http.Cookie{
		Name:  "refreshToken",
		Value: refreshToken,
	}
	http.SetCookie(w, refreshTokenCookie)
	v, _ := json.Marshal(token.TokenResponseBody{AccessToken: accessToken})
	w.Write(v)
}

// Verify the Apple authorization code
func getAppleVerificationResponseBody(authCode string) ([]byte, error) {
	v := url.Values{}
	v.Set("client_id", os.Getenv("APPLE_CLIENT_ID"))
	v.Set("client_secret", os.Getenv("APPLE_CLIENT_SECRET"))
	v.Set("code", authCode)
	v.Set("grant_type", "authorization_code")

	resp, err := http.PostForm("https://appleid.apple.com/auth/token", v)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return make([]byte, 0), err
	}

	return body, nil
}

func getIdTokenFromAppleResponseBody(body []byte) (string, error) {
	var data AppleValidationResponse
	err := json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}

	return data.IdToken, nil
}

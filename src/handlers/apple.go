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
func AppleHandler(w http.ResponseWriter, r *http.Request) {
	// https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api

	// Get the auth code from the request
	var authCode string = r.FormValue("code")

	// Make the verification request
	body, err := getAppleVerificationResponseBody(authCode)

	if err != nil {
		http.Error(w, "Apple verification request failed", 400)
		return
	}

	idToken, err := getIdTokenFromResponseBody(body)

	if err != nil {
		http.Error(w, "Malformed apple verification response", 400)
		return
	}

	sub, err := token.GetSubFromIdToken(idToken, "https://appleid.apple.com/")

	// Create refresh token
	refreshToken := sub

	// Create access token
	accessToken := "spaghetti"

	// Put the refresh token in a cookie and put the access token in the body
	refreshTokenCookie := &http.Cookie{
		Name:  "refreshToken",
		Value: refreshToken,
	}
	http.SetCookie(w, refreshTokenCookie)

	w.Write([]byte(accessToken))
}

// Verify the Apple authorization code
func getAppleVerificationResponseBody(authCode string) ([]byte, error) {
	// Build the verification request
	v := url.Values{}
	v.Set("client_id", os.Getenv("APPLE_CLIENT_ID"))
	v.Set("client_secret", os.Getenv("APPLE_CLIENT_SECRET"))
	v.Set("code", authCode)
	v.Set("grant_type", "authorization_code")

	// Perform the request
	resp, err := http.PostForm("https://appleid.apple.com/auth/token", v)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return make([]byte, 0), err
	}

	return body, nil
}

type AppleValidationResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

func getIdTokenFromResponseBody(body []byte) (string, error) {
	var data AppleValidationResponse
	err := json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}

	return data.IdToken, nil
}

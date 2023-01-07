package handlers

import (
	"bthreader/auth-server/src/utils"

	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

func AppleHandler(w http.ResponseWriter, r *http.Request) {
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

	sub, err := utils.GetSubFromIdToken(idToken, "https://appleid.apple.com/")

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

func getAppleVerificationResponseBody(authCode string) (string, error) {
	// Build the verification request
	v := url.Values{}
	v.Set("client_id", os.Getenv("APPLE_CLIENT_ID"))
	v.Set("client_secret", os.Getenv("APPLE_CLIENT_SECRET"))
	v.Set("code", authCode)
	v.Set("grant_type", "authorization_code")

	// Perform the request
	resp, err := http.PostForm("https://appleid.apple.com/auth/token", v)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func getIdTokenFromResponseBody(body string) (string, error) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(body), &data)
	if err != nil {
		return "", err
	}

	return data["id_token"].(string), nil
}

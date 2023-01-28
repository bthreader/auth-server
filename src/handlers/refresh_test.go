package handlers

import (
	"bthreader/auth-server/src/token"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joho/godotenv"
)

func TestRefreshSuccess(t *testing.T) {
	godotenv.Load("../../.env")
	ts := httptest.NewServer(http.HandlerFunc(RefreshHandler))
	defer ts.Close()

	refreshToken, err := token.GenerateToken(token.RefreshToken, "Jeff")
	if err != nil {
		t.Logf("refresh token generation failed: %v", err)
		t.FailNow()
	}

	refreshTokenCookie := &http.Cookie{
		Name:  "refresh_token",
		Value: refreshToken,
	}
	req, _ := http.NewRequest("POST", ts.URL, nil)
	req.AddCookie(refreshTokenCookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("request failed: %v", err)
		t.FailNow()
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	respBody := &token.TokenResponseBody{}
	err = json.Unmarshal(respBodyBytes, respBody)

	if err != nil {
		t.Logf("error unmarshalling response body: %v", err)
		t.FailNow()
	}
}

func TestRefreshFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(RefreshHandler))
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", nil)

	if err != nil {
		t.Logf("error making request: %v", err)
		t.FailNow()
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Logf("wrong status code, expected 400 received %v", resp.StatusCode)
		t.FailNow()
	}
}

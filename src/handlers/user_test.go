package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestSuccess(t *testing.T) {
	godotenv.Load("../../.env")
	ts := httptest.NewServer(http.HandlerFunc(UserHandler))
	defer ts.Close()

	upMock := UserPassword{
		User:     os.Getenv("ADMIN_USER"),
		Password: os.Getenv("ADMIN_PASSWORD"),
	}

	requestBody, _ := json.Marshal(upMock)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(requestBody))

	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	respBodyBytes, _ := io.ReadAll(resp.Body)
	respBody := string(respBodyBytes)

	if resp.Status != "200 OK" {
		t.Log("request failed")
		t.Logf("response status: %s", resp.Status)
		t.Logf("response body: %s", respBody)
		t.FailNow()
	}

	if respBody == "" {
		t.Log("no access token received")
		t.FailNow()
	}
}

func TestBadRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(UserHandler))
	defer ts.Close()

	type BadObject struct {
		Spaghetti string
		Bolognese string
	}
	badObject := BadObject{
		Spaghetti: "spaghetti",
		Bolognese: "bolognese",
	}

	requestBody, _ := json.Marshal(badObject)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(requestBody))

	if err != nil {
		t.Log(err)
		t.Fail()
	}
	if resp.Status == "200 OK" {
		t.Log("request didn't fail")
		t.Fail()
	}

	// Check error message
	respBodyBytes, _ := io.ReadAll(resp.Body)
	respBody := string(respBodyBytes)

	if strings.TrimRight(respBody, "\n") != malformedBodyMsg {
		t.Logf("expected: %+q", malformedBodyMsg)
		t.Logf("received: %+q", strings.TrimRight(respBody, "\n"))
		t.Fail()
	}
}

func TestBadCreds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(UserHandler))
	defer ts.Close()

	upMock := UserPassword{
		User:     "spaghetti",
		Password: "bolognese",
	}

	requestBody, _ := json.Marshal(upMock)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(requestBody))

	if err != nil {
		t.Log(err)
		t.Fail()
	}
	if resp.Status == "200 OK" {
		t.Fail()
	}

	// Check error message
	respBodyBytes, _ := io.ReadAll(resp.Body)
	respBody := string(respBodyBytes)

	if strings.TrimSpace(respBody) != "Incorrect username or password please try again" {
		t.Log(respBody)
		t.Fail()
	}
}

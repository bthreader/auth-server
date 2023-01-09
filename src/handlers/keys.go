package handlers

import (
	"bthreader/auth-server/src/oauth"

	"encoding/json"
	"net/http"
)

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	key := oauth.JwksKey{
		Kty: "hello",
		Kid: "hello",
		Use: "hello",
		Alg: "hello",
		N:   "hello",
		E:   "hello",
	}

	keys := oauth.JwksResponse{
		Keys: append(make([]oauth.JwksKey, 0), key),
	}

	b, _ := json.Marshal(keys)

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

	return
}

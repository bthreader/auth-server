package handlers

import (
	"bthreader/auth-server/src/utils"
	"encoding/json"
	"net/http"
)

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	key := utils.JwksKey{
		Kty: "hello",
		Kid: "hello",
		Use: "hello",
		Alg: "hello",
		N:   "hello",
		E:   "hello",
	}

	keys := utils.JwksResponse{
		Keys: append(make([]utils.JwksKey, 0), key),
	}

	b, _ := json.Marshal(keys)

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

	return
}

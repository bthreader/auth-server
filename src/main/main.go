package main

import (
	"bthreader/auth-server/src/handlers"
	"log"
	"net/http"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	http.HandleFunc("/token/apple", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(POST, w, r, handlers.AppleHandler)
	})
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(POST, w, r, handlers.UserTokenHandler)
	})
	http.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(GET, w, r, handlers.KeysHandler)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Ensures a request has a certain method before routing it onto a handler
func forceMethod(
	m HTTPMethod,
	w http.ResponseWriter,
	r *http.Request,
	h func(http.ResponseWriter, *http.Request),
) {
	if r.Method != string(m) {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	h(w, r)
}

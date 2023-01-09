package main

import (
	"bthreader/auth-server/src/handlers"
	"fmt"
	"html"
	"log"
	"net/http"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	http.HandleFunc("/token/apple", handlers.AppleHandler)
	http.HandleFunc("/token", handlers.UserTokenHandler)
	http.HandleFunc("/keys", handlers.KeysHandler)

	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

package main

import (
	"bthreader/auth-server/src/handlers"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch os.Getenv("ENV") {
		case "DEV":
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8000")
		case "PROD":
			w.Header().Set("Access-Control-Allow-Origin", "https://bthreader.github.io")
		default:
			http.Error(w, "Error validating origin", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(w, r)
	})
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	mux := http.NewServeMux()

	// http.HandleFunc("/token/apple", func(w http.ResponseWriter, r *http.Request) {
	// 	forceMethod(POST, w, r, handlers.AppleHandler)
	// })
	mux.HandleFunc("/token/google", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(POST, w, r, handlers.GoogleHandler)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(POST, w, r, handlers.UserHandler)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(GET, w, r, handlers.KeysHandler)
	})
	mux.HandleFunc("/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		forceMethod(POST, w, r, handlers.RefreshHandler)
	})

	log.Fatal(http.ListenAndServe(":8080", corsMiddleware(mux)))
}

// Ensures a request has a certain method before routing it onto a handler
func forceMethod(
	m HTTPMethod,
	w http.ResponseWriter,
	r *http.Request,
	h func(http.ResponseWriter, *http.Request),
) {
	var method HTTPMethod = HTTPMethod(r.Method)
	switch method {
	case m:
		h(w, r)
	case OPTIONS:
		return
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}

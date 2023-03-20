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
	listenAddr := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		listenAddr = ":" + val
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/token/google", handlers.GoogleHandler)
	mux.HandleFunc("/api/token", handlers.UserHandler)
	mux.HandleFunc("/api/keys", handlers.KeysHandler)
	mux.HandleFunc("/api/token/refresh", handlers.RefreshHandler)
	log.Fatal(http.ListenAndServe(listenAddr, corsMiddleware(mux)))
}

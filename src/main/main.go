package main

import (
	"bthreader/auth-server/src/handlers"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

//

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
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

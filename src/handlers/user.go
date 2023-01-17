package handlers

import (
	"bthreader/auth-server/src/token"
	"os"

	"encoding/json"
	"io"
	"net/http"
)

const malformedBodyMsg = `Malformed body, please make the request in the form:
	'{"user": yourusernamehere, "password": yourpasswordhere}'`

func UserHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	var up UserPassword
	err = json.Unmarshal(body, &up)

	if err != nil || up.User == "" || up.Password == "" {
		http.Error(w, malformedBodyMsg, http.StatusBadRequest)
		return
	}

	if up.User == os.Getenv("ADMIN_USER") && up.Password == os.Getenv("ADMIN_PASSWORD") {
		// Authenticated
		token, err := token.GenerateToken(token.AccessToken, "user")
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		w.Write([]byte(token))
		return
	}

	http.Error(w, "Incorrect username or password please try again", http.StatusBadRequest)
}

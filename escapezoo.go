package main

import (
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var sessionKey = []byte(os.Getenv("SESSION_KEY"))

func main() {
	http.HandleFunc("/", MyHandler)
	http.ListenAndServe(":8080", nil)
}

func MyHandler(w http.ResponseWriter, r *http.Request) {
	// Get the cookie named "cookiepath" from the request
	cookie, err := r.Cookie("zoo")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}

	// Use the value of the "cookiepath" cookie as the cookie path for the session store
	store := sessions.NewFilesystemStore(cookie.Value, sessionKey)

	// Get a session from the store
	session, err := store.Get(r, "gorilla")
	if err != nil {
		http.Error(w, "Error getting session", http.StatusInternalServerError)
		return
	}

	// Set some session values
	session.Values["foo"] = "bar"
	session.Values[42] = 43

	// Save the session
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	w.Header().Set("Content-Type", "text/plain")
	//w.Write([]byte("Session data saved successfully!"))
}


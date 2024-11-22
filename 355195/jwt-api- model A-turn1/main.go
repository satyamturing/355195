package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type client struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

var clients []client

func RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newClient client
	err := json.NewDecoder(r.Body).Decode(&newClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newClient.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newClient.Password = string(hashedPassword)

	token := generateJWT(newClient)

	newClient.Token = token
	clients = append(clients, newClient)

	json.NewEncoder(w).Encode(newClient)
}

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = tokenString[7:]
		}

		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Token invalid", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*jwt.StandardClaims)
		if !ok || claims.Subject == "" {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		var loggedClient client
		for _, client := range clients {
			if strconv.Itoa(client.ID) == claims.Subject {
				loggedClient = client
				break
			}
		}
		if loggedClient.ID == 0 {
			http.Error(w, "Client not found", http.StatusForbidden)
			return
		}

		newToken := generateJWT(loggedClient)
		loggedClient.Token = newToken

		r.Header.Set("X-Auth-Username", loggedClient.Username)
		next.ServeHTTP(w, r)
	})
}

func generateJWT(c client) string {
	claims := &jwt.StandardClaims{
		Subject: strconv.Itoa(c.ID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Fatalf("Error generating token: %v", err)
	}
	return tokenString
}

func main() {
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET environment variable not set")
	}

	r := mux.NewRouter()

	r.HandleFunc("/register", RegisterClient).Methods("POST")

	r.Handle("/profile", Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to your profile!"))
	})))

	fmt.Println("Server is running on https://localhost:8443")
	log.Fatal(http.ListenAndServe(":8443", r))
}

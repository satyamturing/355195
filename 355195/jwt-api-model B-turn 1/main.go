package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	JWT      string `json:"jwt"`
}

var clients []Client

// Returns the client with the given username or nil if not found.
func getClientByUsername(username string) *Client {
	for _, c := range clients {
		if c.Username == username {
			return &c
		}
	}
	return nil
}

// Generates a JWT token with the provided username and password.
func generateJWT(username string) (string, error) {
	// Creating a new Secret key. Should be replaced by a secure key.
	secretKey := []byte("super-secret") // You need to change this for production!

	user := getClientByUsername(username)
	if user == nil {
		return "", fmt.Errorf("user not found")
	}

	claims := &jwt.StandardClaims{
		Subject:   username,
		Issuer:    "jwt-auth-middleware",
		ExpiresAt: jwt.At(time.Now().Add(time.Hour * 1)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	// Store the JWT token in the client's record
	user.JWT = signedToken
	clients = updateClient(user)

	return signedToken, nil
}

func updateClient(user *Client) []Client {
	// Update client list with the new JWT token.
	for i, c := range clients {
		if c.Username == user.Username {
			clients[i] = *user
			return clients
		}
	}
	// If the user is not found, add them to the list.
	return append(clients, *user)
}

func isValidPassword(hashed string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	return err == nil
}

// Middleware function to handle JWT authentication.
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT token from the request header.
		authToken := r.Header.Get("Authorization")
		if authToken == "" {
			http.Error(w, "Missing Authorization token", http.StatusUnauthorized)
			return
		}
		token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
			// You should validate the signing method here, but since we are using HS256 it's fine
			secretKey := []byte("super-secret") // Replace this with a secure key
			return secretKey, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract the subject (username) from the token claims.
		claims, ok := token.Claims.(*jwt.StandardClaims)
		if !ok || !claims.Valid {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Define the routes
	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var client Client
		if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
			http.Error(w, "Unable to parse request", http.StatusBadRequest)
			return
		}
		clients = append(clients, client)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(client)
	}).Methods("POST")

	r.Handle("/profile", jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the username from the JWT claims
		authToken := r.Header.Get("Authorization")
		claims, _ := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
			secretKey := []byte("super-secret") // Replace this with a secure key
			return secretKey, nil
		})
		username := claims.(*jwt.StandardClaims).Subject
		w.Write([]byte(fmt.Sprintf("Welcome to your profile, %s!", username)))
	})))

	// Start the server
	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", r)
}

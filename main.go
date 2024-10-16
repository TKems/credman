package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Define JWT Secret Key
var jwtSecret = []byte("your_secret_key")

// Database connection
var db *sql.DB

// Structs
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	ApiKey   string `json:"api_key"`
	Authenticator []byte `json:"authenticator"` //Future Passkey option
}

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Helper: Connect to SQLite database
func connectDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./database.db")
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Helper: Hash a password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Helper: Check if a password is correct
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Helper: Create JWT token
func createJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	return tokenString, err
}

// Helper: Validate JWT token from Authorization header
func validateJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return claims, nil
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check credentials against DB
	var user User
	row := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = ?", loginData.Username)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		err =: LogToFile("webauth.log", "LOGIN Bad or Unknown Username 401: Unauthorized login attempt from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err != nil {
			log.Fatalf("Error logging to file: %v", err)
		}
		return
	}

	if !checkPasswordHash(loginData.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		err =: LogToFile("webauth.log", "LOGIN Bad or Unknown Password 401: Unauthorized login attempt from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err != nil {
			log.Fatalf("Error logging to file: %v", err)
		}
		return
	}

	// Create JWT token
	token, err := createJWT(user.Username)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	// Respond with JWT
	respondWithJSON(w, http.StatusOK, map[string]string{
		"token": token,
	})
}

// Add data handler (JWT protected)
func addDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate JWT
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := validateJWT(tokenStr)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		err =: LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err != nil {
			log.Fatalf("Error logging to file: %v", err)
		}
		return
	}

	// Decode request body
	var newData struct {
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		System   string   `json:"system"`
		Tags     []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&newData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Insert data into DB
	tags := strings.Join(newData.Tags, ",")
	_, err = db.Exec("INSERT INTO data (name, type, username, system, tags) VALUES (?, ?, ?, ?, ?)",
		newData.Name, newData.Type, claims.Username, newData.System, tags)
	if err != nil {
		http.Error(w, "Failed to insert data", http.StatusInternalServerError)
		return
	}

	// Respond with success
	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Data added successfully",
	})
}

// Respond with JSON helper
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Error marshaling JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}


func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate JWT
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := validateJWT(tokenStr)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		err =: LogToFile("webauth.log", "SEARCH 401: Unauthorized search from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err != nil {
			log.Fatalf("Error logging to file: %v", err)
		}
		return
	}



}


// LogToFile appends log messages to a specified log file.
func LogToFile(logFile string, msg string) error {
	// Open the log file in append mode
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a new logger that writes to the log file
	logger := log.New(file, "", log.LstdFlags)

	// Get the name of the calling function
	_, fn, line, ok := runtime.Caller(1)
	if !ok {
		fn = "unknown"
		line = 0
	}

	// Log the message with a timestamp and function name
	logger.Printf("[%s] %s:%d - %s\n", time.Now().Format(time.RFC3339), fn, line, msg)

	return nil
}

func main() {
	var err error
	db, err = connectDB()
	if err != nil {
		log.Fatalf("Could not connect to the database: %v", err)
	}
	defer db.Close()

	// Routes
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/data", addDataHandler)
	http.HandleFunc("/api/search", searchHandler)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting server on :%s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

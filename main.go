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
	"runtime"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Define JWT Secret Key
var jwtSecret = []byte("supersecretkey")

// Database connection
var db *sql.DB

// Structs
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	PasswordHash string `json:"passwordhash"`
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
func validateJWT(tokenStr string) (bool, error) {
	//claims := &Claims{}
	//token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
	//	return jwtSecret, nil
	//})

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	
	claims := token.Claims.(jwt.MapClaims)
	if err != nil || !token.Valid {
		return false, err
	}

	// Get username from JWT claims
	username, ok := claims["username"].(string)
	if !ok {
		//JWT does not contain the correct claim (username)
		//TODO: Add logging
		return false, err
	}

	// Validate the user against the SQLite database
	if !validateUserInDB(username) {
		// User may have been removed from DB
		//TODO: Add logging
		return false, err
	} else {
		return bool(true), err
	}

}

// validateUserInDB checks if the user exists in the SQLite database
func validateUserInDB(username string) bool {

	// Query the user by ID
	var user User
	err := db.QueryRow("SELECT id, username FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username)

	if err != nil {
		if err == sql.ErrNoRows {
			// User not found
			return false
		}
		log.Fatal(err)
	}

	// User exists
	return true
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
	row := db.QueryRow("SELECT username, passwordhash FROM users WHERE username = ?", loginData.Username)
	err := row.Scan(&user.Username, &user.PasswordHash)
	if err != nil {
		log.Println(err) 
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		err2 := LogToFile("webauth.log", "LOGIN Bad or Unknown Username 401: Unauthorized login attempt from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err2 != nil {
			log.Fatalf("Error logging to file: %v", err2)
		}
		return
	}

	if !checkPasswordHash(loginData.Password, user.PasswordHash) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		err3 := LogToFile("webauth.log", "LOGIN Bad or Unknown Password 401: Unauthorized login attempt from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err3 != nil {
			log.Println(err3) 
			log.Fatalf("Error logging to file: %v", err3)
		}
		return
	}

	// Create JWT token
	token, err := createJWT(user.Username)
	if err != nil {
		log.Println(err)
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
	validUser, err := validateJWT(tokenStr)
	if err != nil {
		log.Println(err) 
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err4 != nil {
			log.Fatalf("Error logging to file: %v", err4)
		}
		return
	}

	if !validUser {
		//User is not valid for some reason... Check the JWT validation logic
		return
	}

	// Decode request body
	var newData struct {
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		Username     string   `json:"username"`
		System   string   `json:"system"`
		Service   string   `json:"service"`
		Shared   string   `json:"shared"`
		TSI   string   `json:"tsi"`
		TeamNum   string   `json:"teamnum"`
		Value   string   `json:"value"`
		Cracked   string   `json:"cracked"`
		Tags     string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&newData); err != nil {
		log.Println(err) 
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Insert data into DB
	
	_, err = db.Exec("INSERT INTO data (name, type, username, system, service, shared, tsi, teamnum, value, cracked, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		newData.Name, newData.Type, newData.Username, newData.System, newData.Service, newData.Shared, newData.TSI, newData.TeamNum, newData.Value, newData.Cracked, newData.Tags)
	if err != nil {
		log.Println(err) 
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
		log.Println(err) 
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
	validUser, err := validateJWT(tokenStr)
	if err != nil {
		log.Println(err) 
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+ r.RemoteAddr + " or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err4 != nil {
			log.Fatalf("Error logging to file: %v", err4)
		}
		return
	}

	if !validUser {
		//User is not valid for some reason... Check the JWT validation logic
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	type SearchResults struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Type string `json:"type"`
		Username string `json:"username"`
		System string `json:"system"`
		Service string `json:"service"`
		TeamNum string `json:"teamnum"`
		Value   string   `json:"value"`
	}

	// Parse query parameters
	searchTerm := r.URL.Query().Get("q")
	
	if searchTerm == "" {
		// Return all results if query is empty
		query := `
		SELECT id, name, type, username, system, service, teamnum, value 
		FROM data
		`
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer rows.Close()

		// Create a slice to hold the results
		var results []SearchResults

		// Iterate over the rows and scan the data into the struct
		for rows.Next() {
			var result SearchResults
			err = rows.Scan(&result.ID, &result.Name, &result.Type, &result.Username, &result.System, &result.Service, &result.TeamNum, &result.Value)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			results = append(results, result)
		}

		// Check for errors during row iteration
		if err = rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Convert the results to JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
		return
	}

	// SEARCH LOGIC HERE

	// Query the database for matching values across columns
	query := `
		SELECT id, name, type, username, system, service, teamnum, value 
		FROM data 
		WHERE name LIKE ? OR type LIKE ? OR username LIKE ? OR system LIKE ? OR service LIKE ? OR teamnum LIKE ? OR value LIKE ?
	`
	rows, err := db.Query(query, "%"+searchTerm+"%", "%"+searchTerm+"%", "%"+searchTerm+"%", "%"+searchTerm+"%", "%"+searchTerm+"%", "%"+searchTerm+"%", "%"+searchTerm+"%")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the results
	var results []SearchResults

	// Iterate over the rows and scan the data into the struct
	for rows.Next() {
		var result SearchResults
		err = rows.Scan(&result.ID, &result.Name, &result.Type, &result.Username, &result.System, &result.Service, &result.TeamNum, &result.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, result)
	}

	// Check for errors during row iteration
	if err = rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert the results to JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)

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

	// Serve Static HTML
	http.Handle("/", http.FileServer(http.Dir("./html")))

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting server on :%s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

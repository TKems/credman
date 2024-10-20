package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Define JWT Secret Key
// TODO: change this to be a random value on every launch of the server. (kills old JWTs)
var jwtSecret = []byte("supersecretkey")

// Database connection
var db *sql.DB

// Structs
type User struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	PasswordHash  string `json:"passwordhash"`
	ApiKey        string `json:"api_key"`
	Authenticator []byte `json:"authenticator"` //Future Passkey option
}

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Helper: Connect to SQLite database
func connectDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "./database.db")
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
		err2 := LogToFile("webauth.log", "LOGIN Bad or Unknown Username 401: Unauthorized login attempt from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
		if err2 != nil {
			log.Fatalf("Error logging to file: %v", err2)
		}
		return
	}

	if !checkPasswordHash(loginData.Password, user.PasswordHash) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		err3 := LogToFile("webauth.log", "LOGIN Bad or Unknown Password 401: Unauthorized login attempt from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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
		Name     string `json:"name"`
		Type     string `json:"type"`
		Username string `json:"username"`
		System   string `json:"system"`
		Service  string `json:"service"`
		Shared   string `json:"shared"`
		TSI      string `json:"tsi"`
		TeamNum  string `json:"teamnum"`
		Value    string `json:"value"`
		Cracked  string `json:"cracked"`
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

// Handle search queries (including empty ones during first load of the table)
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Username string `json:"username"`
		System   string `json:"system"`
		Service  string `json:"service"`
		TeamNum  string `json:"teamnum"`
		Value    string `json:"value"`
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

// Create the database tables if they do not exist
func createDatabase() error {

	// Create a table for users
	createUsersTableSQL := `CREATE TABLE IF NOT EXISTS "users" (
		"id"	INTEGER,
		"username"	TEXT NOT NULL,
		"email"	TEXT,
		"passwordhash"	TEXT NOT NULL,
		"apikey"	TEXT,
		"authenticator"	BLOB,
		PRIMARY KEY("id" AUTOINCREMENT)
	)`

	// Execute the table creation
	if _, err := db.Exec(createUsersTableSQL); err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	// Create a table for data
	createDataTableSQL := `CREATE TABLE IF NOT EXISTS "data" (
		"id"	INTEGER NOT NULL,
		"name"	TEXT NOT NULL,
		"type"	TEXT,
		"username"	TEXT,
		"system"	TEXT,
		"service"	TEXT,
		"tsi"	INTEGER,
		"shared"	INTEGER,
		"teamnum"	INTEGER,
		"value"	TEXT NOT NULL,
		"cracked"	INTEGER,
		"tags"	TEXT,
		PRIMARY KEY("id")
	)`

	// Execute the table creation
	if _, err := db.Exec(createDataTableSQL); err != nil {
		log.Fatalf("Failed to create data table: %v", err)
	}

	// Check if Teams table exists and fill it with data if it doesn't
	// Table name to check
	tableName := "teams"
	tableExists := false

	// Query to check if the table exists
	query := fmt.Sprintf(`SELECT name FROM sqlite_master WHERE type='table' AND name='%s';`, tableName)
	row := db.QueryRow(query)

	var name string
	err := row.Scan(&name)

	if err == sql.ErrNoRows {
		// Table does not exist
		tableExists = false
	} else if err != nil {
		// Other error occurred
		log.Fatal(err)
	} else {
		// Table exists
		tableExists = true
	}

	if !tableExists {
		// Create the teams table
		createTeamTableSQL := `CREATE TABLE IF NOT EXISTS "teams" (
			"id"	INTEGER NOT NULL,
			"name"	TEXT,
			"status"	INTEGER,
			PRIMARY KEY("id")
		)`
		// Execute table creation
		if _, err := db.Exec(createTeamTableSQL); err != nil {
			log.Fatalf("Failed to create team table: %v", err)
		}

		// Create a teams (1-40) with default names and all active
		fillTeamTableSQL := `INSERT INTO teams (id, name, status) VALUES 
			(1, 'Team 1', 1),
			(2, 'Team 2', 1),
			(3, 'Team 3', 1),
			(4, 'Team 4', 1),
			(5, 'Team 5', 1),
			(6, 'Team 6', 1),
			(7, 'Team 7', 1),
			(8, 'Team 8', 1),
			(9, 'Team 9', 1),
			(10, 'Team 10', 1),
			(11, 'Team 11', 1),
			(12, 'Team 12', 1),
			(13, 'Team 13', 1),
			(14, 'Team 14', 1),
			(15, 'Team 15', 1),
			(16, 'Team 16', 1),
			(17, 'Team 17', 1),
			(18, 'Team 18', 1),
			(19, 'Team 19', 1),
			(20, 'Team 20', 1),
			(21, 'Team 21', 1),
			(22, 'Team 22', 1),
			(23, 'Team 23', 1),
			(24, 'Team 24', 1),
			(25, 'Team 25', 1),
			(26, 'Team 26', 1),
			(27, 'Team 27', 1),
			(28, 'Team 28', 1),
			(29, 'Team 29', 1),
			(30, 'Team 30', 1),
			(31, 'Team 31', 1),
			(32, 'Team 32', 1),
			(33, 'Team 33', 1),
			(34, 'Team 34', 1),
			(35, 'Team 35', 1),
			(36, 'Team 36', 1),
			(37, 'Team 37', 1),
			(38, 'Team 38', 1),
			(39, 'Team 39', 1),
			(40, 'Team 40', 1);
			`
		// Execute to fill teams table with default values
		if _, err := db.Exec(fillTeamTableSQL); err != nil {
			log.Fatalf("Failed to fill team table with defaults: %v", err)
		}

	} else {
		fmt.Printf("Table '%s' exists. Skipping create and fill...\n", tableName)
	}

	return nil
}

// Active Teams API Handler
// Returns a JSON array of active teams
// TODO: Support team names
func activeTeamsHandler(w http.ResponseWriter, r *http.Request) {

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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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

	type Teams struct {
		ID int `json:"id"`
	}

	// Query to get all active teams (status = 1)
	query := `
		SELECT id
		FROM teams 
		WHERE status=1
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the results
	var results []Teams

	// Iterate over the rows and scan the data into the struct
	for rows.Next() {
		var result Teams
		err = rows.Scan(&result.ID)
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

// Systems API Handler that returns JSON of all system types entered
func systemsHandler(w http.ResponseWriter, r *http.Request) {

	// Only allow POST method
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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

	type Systems struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		Default int    `json:"default"`
	}

	// Query to get all entered systems (machine types such as database, AD, etc.)
	query := `
		SELECT id, name, default
		FROM systems
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the results
	var results []Systems

	// Iterate over the rows and scan the data into the struct
	for rows.Next() {
		var result Systems
		err = rows.Scan(&result.ID, &result.Name, &result.Default)
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

// Services API Handler that returns JSON of all services entered
func servicesHandler(w http.ResponseWriter, r *http.Request) {

	// Only allow POST method
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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

	type Services struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Port     string `json:"port"`
		AuthType int    `json:"authtype"`
	}

	// Query to get all entered systems (machine types such as database, AD, etc.)
	query := `
		SELECT id, name, port, authtype
		FROM services
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the results
	var results []Services

	// Iterate over the rows and scan the data into the struct
	for rows.Next() {
		var result Services
		err = rows.Scan(&result.ID, &result.Name, &result.Port, &result.AuthType)
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

/////// Helpers for SQL Null Management ////////////////

// MarshalJSON for NullString
func (ns *NullString) MarshalJSON() ([]byte, error) {
	if !ns.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(ns.String)
}

// UnmarshalJSON for NullString
func (ns *NullString) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, &ns.String)
	ns.Valid = (err == nil)
	return err
}

// NullString is an alias for sql.NullString data type
type NullString sql.NullString

// Scan implements the Scanner interface for NullString
func (ns *NullString) Scan(value interface{}) error {
	var s sql.NullString
	if err := s.Scan(value); err != nil {
		return err
	}

	// if nil then make Valid false
	if reflect.TypeOf(value) == nil {
		*ns = NullString{s.String, false}
	} else {
		*ns = NullString{s.String, true}
	}

	return nil
}

/////////////// End SQL NULL Management Helpers /////////////////

// Auth Type API Handler that returns JSON of all auth types entered
func authtypeHandler(w http.ResponseWriter, r *http.Request) {

	// Only allow POST method
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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

	type AuthType struct {
		ID         int        `json:"id"`
		Name       string     `json:"name"`
		NumFields  string     `json:"numfields"`
		Field1Name string     `json:"field1name"`
		Field1     string     `json:"field1"`
		Field2Name NullString `json:"field2name"`
		Field2     NullString `json:"field2"`
		Field3Name NullString `json:"field3name"`
		Field3     NullString `json:"field3"`
		Field4Name NullString `json:"field4name"`
		Field4     NullString `json:"field4"`
		Field5Name NullString `json:"field5name"`
		Field5     NullString `json:"field5"`
	}

	// Query to get all entered auth types (up to 5 fields per type)
	query := `
		SELECT id, name, numfields, field1name, field1, field2name, field2, field3name, field3, field4name, field4, field5name, field5,
		FROM authtype
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the results
	var results []AuthType

	// Iterate over the rows and scan the data into the struct
	for rows.Next() {
		var result AuthType
		err = rows.Scan(&result.ID, &result.Name, &result.NumFields, &result.Field1Name, &result.Field1, &result.Field2Name, &result.Field2, &result.Field3Name, &result.Field3, &result.Field4Name, &result.Field4, &result.Field5Name, &result.Field5)
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

// Hashes API Handler that returns JSON of all uncracked hashes
func hashesHandler(w http.ResponseWriter, r *http.Request) {

	// Only allow POST method
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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

	type Hashes struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		Value   string `json:"value"`
		TeamNum int    `json:"teamnum"`
		Cracked int    `json:"cracked"`
		System  string `json:"system"`
	}

	// Query to get all uncracked hashes (cracked=0)
	query := `
		SELECT id, name, value, teamnum, cracked, system
		FROM data
		WHERE cracked=0
	`
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a slice to hold the results
	var results []Hashes

	// Iterate over the rows and scan the data into the struct
	for rows.Next() {
		var result Hashes
		err = rows.Scan(&result.ID, &result.Name, &result.Value, &result.TeamNum, &result.Cracked, &result.System)
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

// Crack API Handler that updates hashes that have been cracked.
// Mainly should be used via the API
func crackHandler(w http.ResponseWriter, r *http.Request) {

	// Only allow POST method
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
		err4 := LogToFile("webauth.log", "ADD DATA 401: Unauthorized add from "+r.RemoteAddr+" or if proxied "+r.Header.Get("X-Forwarded-For"))
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

	// Parse query parameters
	crackedHash := r.URL.Query().Get("cracked")
	dataID := r.URL.Query().Get("id")

	// Insert data into DB
	_, err = db.Exec("UPDATE data SET cracked = 1, value = value || ':' || ? WHERE id=?", crackedHash, dataID)
	if err != nil {
		log.Println(err)
		http.Error(w, "Failed to update data", http.StatusInternalServerError)
		return
	}

	// Respond with success
	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Hash updated successfully",
	})

}

func main() {
	var err error
	db, err = connectDB()
	if err != nil {
		log.Fatalf("Could not connect to the database: %v", err)
	}
	defer db.Close()

	err = createDatabase()
	if err != nil {
		log.Fatalf("Could not create the database: %v", err)
	}

	// Routes
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/data", addDataHandler)
	http.HandleFunc("/api/search", searchHandler)
	http.HandleFunc("/api/hashes", hashesHandler)
	http.HandleFunc("/api/crack", crackHandler)
	http.HandleFunc("/api/activeteams", activeTeamsHandler)
	http.HandleFunc("/api/systems", systemsHandler)
	http.HandleFunc("/api/services", servicesHandler)
	http.HandleFunc("/api/authtype", authtypeHandler)

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

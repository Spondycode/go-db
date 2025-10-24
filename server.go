package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the database
type User struct {
	ID       int       `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Password string    `json:"-"` // Don't expose password in JSON
	IsAdmin  bool      `json:"is_admin"`
	Created  time.Time `json:"created"`
}

// Server holds the database connection and templates
type Server struct {
	DB        *sql.DB
	Templates *template.Template
	Store     *sessions.CookieStore
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ProductRequest represents the request structure for creating/updating products
type ProductRequest struct {
	Name      string  `json:"name"`
	Price     float64 `json:"price"`
	Available bool    `json:"available"`
}

// AuthRequest represents the request structure for login/signup
type AuthRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
}

// AuthResponse represents the response structure for authentication
type AuthResponse struct {
	User    *User  `json:"user,omitempty"`
	Message string `json:"message"`
}

// NewServer creates a new server instance
func NewServer(db *sql.DB) *Server {
	// Parse all templates
	templates := template.Must(template.ParseGlob("templates/*.html"))

	// Create session store with a secret key
	store := sessions.NewCookieStore([]byte("your-secret-key-change-this-in-production"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	}

	return &Server{
		DB:        db,
		Templates: templates,
		Store:     store,
	}
}

// setupRoutes configures all the HTTP routes
func (s *Server) setupRoutes() *mux.Router {
	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))

	// Web routes
	r.HandleFunc("/", s.handleHome).Methods("GET")
	r.HandleFunc("/login", s.handleLoginPage).Methods("GET")
	r.HandleFunc("/signup", s.handleSignupPage).Methods("GET")

	// Authentication API routes
	auth := r.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/login", s.handleLogin).Methods("POST")
	auth.HandleFunc("/signup", s.handleSignup).Methods("POST")
	auth.HandleFunc("/logout", s.handleLogout).Methods("POST")
	auth.HandleFunc("/me", s.handleGetCurrentUser).Methods("GET")

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/products", s.handleGetProducts).Methods("GET")
	api.HandleFunc("/products", s.handleCreateProduct).Methods("POST")
	api.HandleFunc("/products/{id:[0-9]+}", s.handleGetProduct).Methods("GET")
	api.HandleFunc("/products/{id:[0-9]+}", s.handleUpdateProduct).Methods("PUT")
	api.HandleFunc("/products/{id:[0-9]+}", s.handleDeleteProduct).Methods("DELETE")

	return r
}

// handleHome serves the main page
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title string
	}{
		Title: "Product Management System",
	}

	err := s.Templates.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

// handleGetProducts returns all products as JSON
func (s *Server) handleGetProducts(w http.ResponseWriter, r *http.Request) {
	products, err := s.getAllProducts()
	if err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Failed to retrieve products", nil)
		return
	}

	s.sendJSONResponse(w, http.StatusOK, true, "Products retrieved successfully", products)
}

// handleGetProduct returns a single product by ID
func (s *Server) handleGetProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid product ID", nil)
		return
	}

	product, err := s.getProductByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			s.sendJSONResponse(w, http.StatusNotFound, false, "Product not found", nil)
		} else {
			s.sendJSONResponse(w, http.StatusInternalServerError, false, "Failed to retrieve product", nil)
		}
		return
	}

	s.sendJSONResponse(w, http.StatusOK, true, "Product retrieved successfully", product)
}

// handleCreateProduct creates a new product
func (s *Server) handleCreateProduct(w http.ResponseWriter, r *http.Request) {
	var req ProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	// Validation
	if strings.TrimSpace(req.Name) == "" {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Product name is required", nil)
		return
	}

	if req.Price < 0 {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Price cannot be negative", nil)
		return
	}

	product := &Product{
		Name:      strings.TrimSpace(req.Name),
		Price:     req.Price,
		Available: req.Available,
	}

	err := s.addProduct(product)
	if err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Failed to create product", nil)
		return
	}

	s.sendJSONResponse(w, http.StatusCreated, true, "Product created successfully", product)
}

// handleUpdateProduct updates an existing product
func (s *Server) handleUpdateProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid product ID", nil)
		return
	}

	var req ProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	// Validation
	if strings.TrimSpace(req.Name) == "" {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Product name is required", nil)
		return
	}

	if req.Price < 0 {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Price cannot be negative", nil)
		return
	}

	product := &Product{
		ID:        id,
		Name:      strings.TrimSpace(req.Name),
		Price:     req.Price,
		Available: req.Available,
	}

	err = s.updateProduct(product)
	if err != nil {
		if err == sql.ErrNoRows {
			s.sendJSONResponse(w, http.StatusNotFound, false, "Product not found", nil)
		} else {
			s.sendJSONResponse(w, http.StatusInternalServerError, false, "Failed to update product", nil)
		}
		return
	}

	s.sendJSONResponse(w, http.StatusOK, true, "Product updated successfully", product)
}

// handleDeleteProduct deletes a product
func (s *Server) handleDeleteProduct(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid product ID", nil)
		return
	}

	err = s.deleteProduct(id)
	if err != nil {
		if err == sql.ErrNoRows {
			s.sendJSONResponse(w, http.StatusNotFound, false, "Product not found", nil)
		} else {
			s.sendJSONResponse(w, http.StatusInternalServerError, false, "Failed to delete product", nil)
		}
		return
	}

	s.sendJSONResponse(w, http.StatusOK, true, "Product deleted successfully", nil)
}

// Authentication handlers

// handleLoginPage serves the login page
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title string
	}{
		Title: "Login - Product Management System",
	}

	err := s.Templates.ExecuteTemplate(w, "login.html", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

// handleSignupPage serves the signup page
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title string
	}{
		Title: "Sign Up - Product Management System",
	}

	err := s.Templates.ExecuteTemplate(w, "signup.html", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

// handleLogin handles user authentication
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	// Validation
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Username and password are required", nil)
		return
	}

	// Get user from database
	user, err := s.getUserByUsername(strings.TrimSpace(req.Username))
	if err != nil {
		if err == sql.ErrNoRows {
			s.sendJSONResponse(w, http.StatusUnauthorized, false, "Invalid username or password", nil)
		} else {
			s.sendJSONResponse(w, http.StatusInternalServerError, false, "Authentication failed", nil)
		}
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.sendJSONResponse(w, http.StatusUnauthorized, false, "Invalid username or password", nil)
		return
	}

	// Create session
	session, err := s.Store.Get(r, "session-name")
	if err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Session error", nil)
		return
	}

	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["is_admin"] = user.IsAdmin

	if err := session.Save(r, w); err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Session save error", nil)
		return
	}

	// Return user without password
	user.Password = ""
	s.sendJSONResponse(w, http.StatusOK, true, "Login successful", user)
}

// handleSignup handles user registration
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	// Validation
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Username, email, and password are required", nil)
		return
	}

	if len(req.Password) < 6 {
		s.sendJSONResponse(w, http.StatusBadRequest, false, "Password must be at least 6 characters long", nil)
		return
	}

	// Check if user already exists
	existingUser, err := s.getUserByUsername(strings.TrimSpace(req.Username))
	if err != nil && err != sql.ErrNoRows {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Registration failed", nil)
		return
	}
	if existingUser != nil {
		s.sendJSONResponse(w, http.StatusConflict, false, "Username already exists", nil)
		return
	}

	// Check if email already exists
	existingUser, err = s.getUserByEmail(strings.TrimSpace(req.Email))
	if err != nil && err != sql.ErrNoRows {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Registration failed", nil)
		return
	}
	if existingUser != nil {
		s.sendJSONResponse(w, http.StatusConflict, false, "Email already exists", nil)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Password hashing failed", nil)
		return
	}

	// Create user
	user := &User{
		Username: strings.TrimSpace(req.Username),
		Email:    strings.TrimSpace(req.Email),
		Password: string(hashedPassword),
		IsAdmin:  false, // Regular users by default
	}

	err = s.createUser(user)
	if err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Failed to create user", nil)
		return
	}

	// Create session
	session, err := s.Store.Get(r, "session-name")
	if err != nil {
		// User created but session failed - still success
		user.Password = ""
		s.sendJSONResponse(w, http.StatusCreated, true, "User created successfully. Please log in.", user)
		return
	}

	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["is_admin"] = user.IsAdmin

	if err := session.Save(r, w); err != nil {
		// User created but session failed - still success
		user.Password = ""
		s.sendJSONResponse(w, http.StatusCreated, true, "User created successfully. Please log in.", user)
		return
	}

	// Return user without password
	user.Password = ""
	s.sendJSONResponse(w, http.StatusCreated, true, "User created and logged in successfully", user)
}

// handleLogout handles user logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, err := s.Store.Get(r, "session-name")
	if err != nil {
		s.sendJSONResponse(w, http.StatusOK, true, "Logged out successfully", nil)
		return
	}

	// Clear session
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1

	if err := session.Save(r, w); err != nil {
		s.sendJSONResponse(w, http.StatusInternalServerError, false, "Logout error", nil)
		return
	}

	s.sendJSONResponse(w, http.StatusOK, true, "Logged out successfully", nil)
}

// handleGetCurrentUser returns the current logged-in user
func (s *Server) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	session, err := s.Store.Get(r, "session-name")
	if err != nil {
		s.sendJSONResponse(w, http.StatusUnauthorized, false, "Not authenticated", nil)
		return
	}

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		s.sendJSONResponse(w, http.StatusUnauthorized, false, "Not authenticated", nil)
		return
	}

	user, err := s.getUserByID(userID)
	if err != nil {
		s.sendJSONResponse(w, http.StatusUnauthorized, false, "User not found", nil)
		return
	}

	// Remove password from response
	user.Password = ""
	s.sendJSONResponse(w, http.StatusOK, true, "User retrieved successfully", user)
}

// Database methods

// getAllProducts retrieves all products from the database
func (s *Server) getAllProducts() ([]Product, error) {
	query := `
	SELECT id, name, price, available, date_created 
	FROM products 
	ORDER BY id;`

	rows, err := s.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price, &product.Available, &product.DateCreated)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	return products, rows.Err()
}

// getProductByID retrieves a single product by ID
func (s *Server) getProductByID(id int) (*Product, error) {
	query := `
	SELECT id, name, price, available, date_created 
	FROM products 
	WHERE id = $1;`

	var product Product
	err := s.DB.QueryRow(query, id).Scan(&product.ID, &product.Name, &product.Price, &product.Available, &product.DateCreated)
	if err != nil {
		return nil, err
	}

	return &product, nil
}

// addProduct inserts a new product into the database
func (s *Server) addProduct(product *Product) error {
	query := `
	INSERT INTO products (name, price, available) 
	VALUES ($1, $2, $3) 
	RETURNING id, date_created;`

	err := s.DB.QueryRow(query, product.Name, product.Price, product.Available).Scan(&product.ID, &product.DateCreated)
	return err
}

// updateProduct updates an existing product
func (s *Server) updateProduct(product *Product) error {
	query := `
	UPDATE products 
	SET name = $1, price = $2, available = $3 
	WHERE id = $4 
	RETURNING date_created;`

	err := s.DB.QueryRow(query, product.Name, product.Price, product.Available, product.ID).Scan(&product.DateCreated)
	return err
}

// deleteProduct deletes a product by ID
func (s *Server) deleteProduct(id int) error {
	query := `DELETE FROM products WHERE id = $1;`

	result, err := s.DB.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// User database methods

// getUserByUsername retrieves a user by username
func (s *Server) getUserByUsername(username string) (*User, error) {
	query := `
	SELECT id, username, email, password, is_admin, created 
	FROM users 
	WHERE username = $1;`

	var user User
	err := s.DB.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.IsAdmin, &user.Created)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// getUserByEmail retrieves a user by email
func (s *Server) getUserByEmail(email string) (*User, error) {
	query := `
	SELECT id, username, email, password, is_admin, created 
	FROM users 
	WHERE email = $1;`

	var user User
	err := s.DB.QueryRow(query, email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.IsAdmin, &user.Created)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// getUserByID retrieves a user by ID
func (s *Server) getUserByID(id int) (*User, error) {
	query := `
	SELECT id, username, email, password, is_admin, created 
	FROM users 
	WHERE id = $1;`

	var user User
	err := s.DB.QueryRow(query, id).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.IsAdmin, &user.Created)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// createUser inserts a new user into the database
func (s *Server) createUser(user *User) error {
	query := `
	INSERT INTO users (username, email, password, is_admin) 
	VALUES ($1, $2, $3, $4) 
	RETURNING id, created;`

	err := s.DB.QueryRow(query, user.Username, user.Email, user.Password, user.IsAdmin).Scan(&user.ID, &user.Created)
	return err
}

// sendJSONResponse sends a JSON response with the given status code and data
func (s *Server) sendJSONResponse(w http.ResponseWriter, statusCode int, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: success,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

// StartWebServer starts the web server
func StartWebServer() {
	// Database connection
	connStr := "postgres://postgres:secret@localhost:5432/gopgtest?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Create tables if they don't exist
	createProductTableWeb(db)
	createUsersTable(db)

	// Create server
	server := NewServer(db)
	router := server.setupRoutes()

	// Start server
	port := ":8080"
	fmt.Printf("🚀 Server starting on http://localhost%s\n", port)
	fmt.Println("📱 Access the Product Management System in your browser!")

	log.Fatal(http.ListenAndServe(port, router))
}

// Helper functions from main.go

// createProductTableWeb creates the products table if it doesn't exist
func createProductTableWeb(db *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS products (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		price NUMERIC(10,2) NOT NULL,
		available BOOLEAN DEFAULT true,
		date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Failed to create products table:", err)
	}

	fmt.Println("✅ Products table ready!")
}

// createUsersTable creates the users table if it doesn't exist
func createUsersTable(db *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		is_admin BOOLEAN DEFAULT false,
		created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	fmt.Println("✅ Users table ready!")
}

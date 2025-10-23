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

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// Server holds the database connection and templates
type Server struct {
	DB        *sql.DB
	Templates *template.Template
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

// NewServer creates a new server instance
func NewServer(db *sql.DB) *Server {
	// Parse all templates
	templates := template.Must(template.ParseGlob("templates/*.html"))

	return &Server{
		DB:        db,
		Templates: templates,
	}
}

// setupRoutes configures all the HTTP routes
func (s *Server) setupRoutes() *mux.Router {
	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))

	// Web routes
	r.HandleFunc("/", s.handleHome).Methods("GET")

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

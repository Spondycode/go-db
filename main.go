package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Product represents a product in the database
type Product struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Price       float64   `json:"price"`
	Available   bool      `json:"available"`
	DateCreated time.Time `json:"date_created"`
}

// NewProduct creates a new product with default values
func NewProduct(name string, price float64) *Product {
	return &Product{
		Name:      name,
		Price:     price,
		Available: true,
	}
}

func main() {
	connStr := "postgres://postgres:secret@localhost:5432/gopgtest?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	createProductTable(db)
	checkProductTable(db)

	// Start the interactive menu
	runInteractiveMenu(db)
}

func createProductTable(db *sql.DB) {
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

	fmt.Println("Products table created successfully!")
}

func checkProductTable(db *sql.DB) {
	// Check if table exists
	query := `
	SELECT table_name 
	FROM information_schema.tables 
	WHERE table_schema = 'public' 
	AND table_name = 'products';`

	var tableName string
	err := db.QueryRow(query).Scan(&tableName)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("❌ Products table does not exist")
		} else {
			fmt.Printf("Error checking table: %v\n", err)
		}
		return
	}

	fmt.Printf("✅ Table '%s' exists!\n", tableName)

	// Get table structure
	structureQuery := `
	SELECT column_name, data_type, is_nullable, column_default
	FROM information_schema.columns 
	WHERE table_name = 'products' 
	ORDER BY ordinal_position;`

	rows, err := db.Query(structureQuery)
	if err != nil {
		fmt.Printf("Error getting table structure: %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("\nTable Structure:")
	fmt.Println("Column Name\t\tData Type\t\tNullable\tDefault")
	fmt.Println("-----------------------------------------------------------")

	for rows.Next() {
		var columnName, dataType, isNullable string
		var columnDefault sql.NullString

		err := rows.Scan(&columnName, &dataType, &isNullable, &columnDefault)
		if err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			continue
		}

		defaultVal := "NULL"
		if columnDefault.Valid {
			defaultVal = columnDefault.String
		}

		fmt.Printf("%-15s\t%-15s\t%-8s\t%s\n", columnName, dataType, isNullable, defaultVal)
	}
}

// productExists checks if a product with the same name and price already exists
func productExists(db *sql.DB, name string, price float64) (bool, error) {
	query := `SELECT COUNT(*) FROM products WHERE name = $1 AND price = $2;`

	var count int
	err := db.QueryRow(query, name, price).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check if product exists: %w", err)
	}

	return count > 0, nil
}

// addProduct inserts a new product into the database if it doesn't already exist
func addProduct(db *sql.DB, product *Product) error {
	// Check if product already exists
	exists, err := productExists(db, product.Name, product.Price)
	if err != nil {
		return fmt.Errorf("failed to check if product exists: %w", err)
	}

	if exists {
		fmt.Printf("⚠️  Product already exists: %s ($%.2f) - skipping\n", product.Name, product.Price)
		return nil
	}

	query := `
	INSERT INTO products (name, price, available) 
	VALUES ($1, $2, $3) 
	RETURNING id, date_created;`

	err = db.QueryRow(query, product.Name, product.Price, product.Available).Scan(&product.ID, &product.DateCreated)
	if err != nil {
		return fmt.Errorf("failed to insert product: %w", err)
	}

	fmt.Printf("✅ Product added successfully! ID: %d, Name: %s, Price: $%.2f\n",
		product.ID, product.Name, product.Price)
	return nil
}

// addProductIfNotExists is a convenience function that creates and adds a product if it doesn't exist
func addProductIfNotExists(db *sql.DB, name string, price float64) error {
	product := NewProduct(name, price)
	return addProduct(db, product)
} // showAllProducts retrieves and displays all products from the database
func showAllProducts(db *sql.DB) {
	query := `
	SELECT id, name, price, available, date_created 
	FROM products 
	ORDER BY id;`

	rows, err := db.Query(query)
	if err != nil {
		fmt.Printf("Error retrieving products: %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("\n📦 All Products:")
	fmt.Println("ID      Name                            Price   Available       Date Created")
	fmt.Println("-------------------------------------------------------------------------")

	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price, &product.Available, &product.DateCreated)
		if err != nil {
			fmt.Printf("Error scanning product: %v\n", err)
			continue
		}

		availableStr := "Yes"
		if !product.Available {
			availableStr = "No"
		}

		priceStr := fmt.Sprintf("$%.2f", product.Price)
		fmt.Printf("%-8d%-25s%15s %-16s%s\n",
			product.ID,
			product.Name,
			priceStr,
			availableStr,
			product.DateCreated.Format("2006-01-02 15:04:05"))
	}

	if err = rows.Err(); err != nil {
		fmt.Printf("Error iterating over products: %v\n", err)
	}
}

// getProductByID retrieves a single product by its ID and displays name, price, and availability
func getProductByID(db *sql.DB, id int) error {
	query := `
	SELECT name, price, available 
	FROM products 
	WHERE id = $1;`

	var product Product
	err := db.QueryRow(query, id).Scan(&product.Name, &product.Price, &product.Available)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("❌ No product found with ID: %d\n", id)
			return nil
		}
		return fmt.Errorf("failed to get product: %w", err)
	}

	// Display the product details
	availableStr := "Yes"
	if !product.Available {
		availableStr = "No"
	}

	fmt.Printf("\n🎯 Product Details (ID: %d):\n", id)
	fmt.Println("================================")
	fmt.Printf("Name:      %s\n", product.Name)
	fmt.Printf("Price:     $%.2f\n", product.Price)
	fmt.Printf("Available: %s\n", availableStr)
	fmt.Println("================================")

	return nil
}

// getUserInputAndSearchProduct prompts user for ID and searches for the product
func getUserInputAndSearchProduct(db *sql.DB) {
	fmt.Print("\n🔍 Enter a product ID to search: ")

	var id int
	_, err := fmt.Scanf("%d", &id)
	if err != nil {
		fmt.Printf("❌ Invalid input. Please enter a valid number.\n")
		return
	}

	err = getProductByID(db, id)
	if err != nil {
		fmt.Printf("Error retrieving product: %v\n", err)
	}
}

// deleteProductByID deletes a product by its ID after showing details and confirming
func deleteProductByID(db *sql.DB, id int) error {
	// First, get the product to show what we're about to delete
	query := `SELECT name, price, available FROM products WHERE id = $1;`

	var product Product
	err := db.QueryRow(query, id).Scan(&product.Name, &product.Price, &product.Available)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("❌ No product found with ID: %d\n", id)
			return nil
		}
		return fmt.Errorf("failed to get product: %w", err)
	}

	// Show product details
	availableStr := "Yes"
	if !product.Available {
		availableStr = "No"
	}

	fmt.Printf("\n⚠️  Product to be deleted (ID: %d):\n", id)
	fmt.Println("====================================")
	fmt.Printf("Name:      %s\n", product.Name)
	fmt.Printf("Price:     $%.2f\n", product.Price)
	fmt.Printf("Available: %s\n", availableStr)
	fmt.Println("====================================")

	// Ask for confirmation
	fmt.Print("Are you sure you want to delete this product? (y/N): ")
	var confirmation string
	fmt.Scanf("%s", &confirmation)

	if confirmation != "y" && confirmation != "Y" && confirmation != "yes" && confirmation != "Yes" {
		fmt.Println("❌ Deletion cancelled.")
		return nil
	}

	// Perform the deletion
	deleteQuery := `DELETE FROM products WHERE id = $1;`
	result, err := db.Exec(deleteQuery, id)
	if err != nil {
		return fmt.Errorf("failed to delete product: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		fmt.Printf("❌ No product was deleted (ID: %d not found)\n", id)
	} else {
		fmt.Printf("✅ Product successfully deleted! (ID: %d - %s)\n", id, product.Name)
	}

	return nil
}

// getUserInputAndDeleteProduct prompts user for ID and deletes the product
func getUserInputAndDeleteProduct(db *sql.DB) {
	fmt.Print("\n🗑️  Enter a product ID to delete: ")

	var id int
	_, err := fmt.Scanf("%d", &id)
	if err != nil {
		fmt.Printf("❌ Invalid input. Please enter a valid number.\n")
		return
	}

	err = deleteProductByID(db, id)
	if err != nil {
		fmt.Printf("Error deleting product: %v\n", err)
	}
}

// updateProductByID updates a product by its ID after showing current details
func updateProductByID(db *sql.DB, id int) error {
	// First, get the current product details
	query := `SELECT name, price, available FROM products WHERE id = $1;`

	var product Product
	err := db.QueryRow(query, id).Scan(&product.Name, &product.Price, &product.Available)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("❌ No product found with ID: %d\n", id)
			return nil
		}
		return fmt.Errorf("failed to get product: %w", err)
	}

	// Show current product details
	availableStr := "Yes"
	if !product.Available {
		availableStr = "No"
	}

	fmt.Printf("\n📝 Current Product Details (ID: %d):\n", id)
	fmt.Println("=====================================")
	fmt.Printf("Name:      %s\n", product.Name)
	fmt.Printf("Price:     $%.2f\n", product.Price)
	fmt.Printf("Available: %s\n", availableStr)
	fmt.Println("=====================================")

	// Get new values
	fmt.Println("\n✏️  Enter new values (press Enter to keep current value):")

	scanner := bufio.NewScanner(os.Stdin)

	// Update name
	fmt.Printf("New name (current: %s): ", product.Name)
	if scanner.Scan() {
		newName := strings.TrimSpace(scanner.Text())
		if newName != "" {
			product.Name = newName
		}
	}

	// Update price
	fmt.Printf("New price (current: $%.2f): ", product.Price)
	if scanner.Scan() {
		priceInput := strings.TrimSpace(scanner.Text())
		if priceInput != "" {
			newPrice, err := strconv.ParseFloat(priceInput, 64)
			if err != nil {
				fmt.Printf("⚠️  Invalid price format '%s'. Keeping current price.\n", priceInput)
			} else if newPrice < 0 {
				fmt.Println("⚠️  Price cannot be negative. Keeping current price.")
			} else {
				product.Price = newPrice
			}
		}
	}

	// Update availability
	fmt.Printf("Available (current: %s) [y/n]: ", availableStr)
	if scanner.Scan() {
		availableInput := strings.TrimSpace(scanner.Text())
		if availableInput != "" {
			availableInput = strings.ToLower(availableInput)
			if availableInput == "y" || availableInput == "yes" {
				product.Available = true
			} else if availableInput == "n" || availableInput == "no" {
				product.Available = false
			}
		}
	}

	// Confirm update
	newAvailableStr := "Yes"
	if !product.Available {
		newAvailableStr = "No"
	}

	fmt.Printf("\n📋 New Product Details:\n")
	fmt.Println("========================")
	fmt.Printf("Name:      %s\n", product.Name)
	fmt.Printf("Price:     $%.2f\n", product.Price)
	fmt.Printf("Available: %s\n", newAvailableStr)
	fmt.Println("========================")

	fmt.Print("Save these changes? (y/N): ")
	var confirmation string
	fmt.Scanf("%s", &confirmation)

	if confirmation != "y" && confirmation != "Y" && confirmation != "yes" && confirmation != "Yes" {
		fmt.Println("❌ Update cancelled.")
		return nil
	}

	// Perform the update
	updateQuery := `UPDATE products SET name = $1, price = $2, available = $3 WHERE id = $4;`
	result, err := db.Exec(updateQuery, product.Name, product.Price, product.Available, id)
	if err != nil {
		return fmt.Errorf("failed to update product: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		fmt.Printf("❌ No product was updated (ID: %d not found)\n", id)
	} else {
		fmt.Printf("✅ Product successfully updated! (ID: %d - %s)\n", id, product.Name)
	}

	return nil
}

// getUserInputAndUpdateProduct prompts user for ID and updates the product
func getUserInputAndUpdateProduct(db *sql.DB) {
	fmt.Print("\n✏️  Enter a product ID to update: ")

	var id int
	_, err := fmt.Scanf("%d", &id)
	if err != nil {
		fmt.Printf("❌ Invalid input. Please enter a valid number.\n")
		return
	}

	err = updateProductByID(db, id)
	if err != nil {
		fmt.Printf("Error updating product: %v\n", err)
	}
}

// displayMenu shows the main menu options
func displayMenu() {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("           🛍️  PRODUCT MANAGEMENT SYSTEM")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("1. 📋 View all products")
	fmt.Println("2. 🔍 View single product")
	fmt.Println("3. ➕ Add a product")
	fmt.Println("4. ✏️  Update a product")
	fmt.Println("5. 🗑️  Delete a product")
	fmt.Println("6. 🚪 Exit")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Print("Please select an option (1-6): ")
}

// runInteractiveMenu runs the main interactive menu loop
func runInteractiveMenu(db *sql.DB) {
	for {
		displayMenu()

		var choice int
		_, err := fmt.Scanf("%d", &choice)
		if err != nil {
			fmt.Printf("❌ Invalid input. Please enter a number between 1 and 6.\n")
			// Clear the input buffer
			var dummy string
			fmt.Scanln(&dummy)
			continue
		}

		switch choice {
		case 1:
			fmt.Println("\n📋 Displaying all products...")
			showAllProducts(db)
		case 2:
			fmt.Println("\n🔍 Search for a single product...")
			getUserInputAndSearchProduct(db)
		case 3:
			fmt.Println("\n➕ Add a new product...")
			getUserInputAndAddProduct(db)
		case 4:
			fmt.Println("\n✏️  Update a product...")
			getUserInputAndUpdateProduct(db)
		case 5:
			fmt.Println("\n🗑️  Delete a product...")
			getUserInputAndDeleteProduct(db)
		case 6:
			fmt.Println("\n👋 Thank you for using the Product Management System!")
			fmt.Println("Goodbye! 🎉")
			return
		default:
			fmt.Printf("❌ Invalid option: %d. Please choose between 1 and 6.\n", choice)
		}

		// Ask if user wants to continue
		fmt.Print("\nPress Enter to continue...")
		fmt.Scanln()
	}
}

// getUserInputAndAddProduct prompts user for product details and adds it to the database
func getUserInputAndAddProduct(db *sql.DB) {
	fmt.Println("\n➕ Add a New Product")
	fmt.Println("====================")

	scanner := bufio.NewScanner(os.Stdin)

	// Get product name
	fmt.Print("Enter product name: ")
	if !scanner.Scan() {
		fmt.Println("❌ Error reading input.")
		return
	}
	name := strings.TrimSpace(scanner.Text())

	if name == "" {
		fmt.Println("❌ Product name cannot be empty.")
		return
	}

	// Get product price
	fmt.Print("Enter product price ($): ")
	if !scanner.Scan() {
		fmt.Println("❌ Error reading input.")
		return
	}
	priceStr := strings.TrimSpace(scanner.Text())

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		fmt.Printf("❌ Invalid price '%s'. Please enter a valid number.\n", priceStr)
		return
	}

	if price < 0 {
		fmt.Println("❌ Price cannot be negative.")
		return
	}

	// Get availability (optional, defaults to true)
	fmt.Print("Is product available? (y/N, default: y): ")
	available := true // default
	if scanner.Scan() {
		availableInput := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if availableInput == "n" || availableInput == "no" {
			available = false
		}
	}

	// Create and add the product
	product := &Product{
		Name:      name,
		Price:     price,
		Available: available,
	}

	err = addProduct(db, product)
	if err != nil {
		fmt.Printf("❌ Error adding product: %v\n", err)
		return
	}

	fmt.Printf("🎉 Success! Product '%s' added to the database.\n", product.Name)
}

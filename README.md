# Product Management System

A full-stack Go application for managing products with both CLI and web interfaces.

## Features

### 🖥️ CLI Interface
- Interactive menu-driven interface
- Full CRUD operations (Create, Read, Update, Delete)
- Real-time validation and confirmation prompts
- Formatted table display with emojis

### 🌐 Web Interface
- Modern, responsive UI with Tailwind CSS v4
- Modal-based forms for adding and editing products
- Real-time updates without page refresh
- Toast notifications for user feedback
- Professional table layout with hover effects

## Prerequisites

- Go 1.19 or higher
- PostgreSQL database
- Node.js (for Tailwind CSS development)

## Database Setup

1. Create a PostgreSQL database:
   ```sql
   CREATE DATABASE gopgtest;
   ```

2. Update the connection string in both `main.go` and `server.go` if needed:
   ```go
   connStr := "postgres://postgres:secret@localhost:5432/gopgtest?sslmode=disable"
   ```

## Installation

1. Clone the repository
2. Install Go dependencies:
   ```bash
   go mod tidy
   ```

3. Install Node.js dependencies (for Tailwind CSS):
   ```bash
   npm install
   ```

## Usage

### CLI Mode (Default)
Run the application without arguments for interactive CLI mode:

```bash
go run .
```

Features:
- 📋 View all products
- 🔍 View single product by ID
- ➕ Add a new product
- ✏️ Update existing product
- 🗑️ Delete product (with confirmation)
- 🚪 Exit

### Web Mode
Start the web server:

```bash
go run . web
```

Then open your browser and navigate to: `http://localhost:8080`

Features:
- Responsive design that works on desktop and mobile
- Add products using the modal form
- Edit products inline
- Delete products with confirmation dialogs
- Real-time data updates
- Professional UI with smooth animations

## API Endpoints

The web server provides a REST API:

- `GET /api/products` - Get all products
- `GET /api/products/{id}` - Get a specific product
- `POST /api/products` - Create a new product
- `PUT /api/products/{id}` - Update a product
- `DELETE /api/products/{id}` - Delete a product

### Request/Response Format

**Product Object:**
```json
{
  "id": 1,
  "name": "Sample Product",
  "price": 29.99,
  "available": true,
  "date_created": "2023-10-23T10:00:00Z"
}
```

**API Response:**
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { /* product or array of products */ }
}
```

## Development

### Tailwind CSS Development

The project uses Tailwind CSS v4 with local compilation. Source CSS is in `src/input.css` and compiles to `static/styles.css`.

#### Build CSS once:
```bash
npm run build-css
```

#### Watch for changes during development:
```bash
npm run watch-css
```

#### Run both CSS watcher and web server together:
```bash
npm run dev
```

#### Manual Tailwind build:
```bash
npx tailwindcss -i ./src/input.css -o ./static/styles.css --watch
```

### Building for Production
```bash
npm run build
```

This will build the CSS and compile the Go binary.

### Running Tests
```bash
go test ./...
```

## Technologies Used

### Backend
- **Go** - Main programming language
- **PostgreSQL** - Database
- **Gorilla Mux** - HTTP router for web server
- **lib/pq** - PostgreSQL driver

### Frontend
- **HTML5** - Markup
- **Tailwind CSS v4** - Styling framework
- **JavaScript** - Client-side functionality
- **Inter Font** - Typography

## Copilot Development Story

I started with my own basic Go code and used GitHub Copilot in Agent mode to build this complete product management system. Copilot helped create both the CLI interface and web frontend, fixed issues along the way, and even suggested improvements before I asked for them. Using a PostgreSQL database in a Docker container.
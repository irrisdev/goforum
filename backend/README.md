# GoForum

A modern, lightweight discussion forum backend built with Go.

## Features

- **User Management**
  - Secure registration and authentication
  - JWT-based stateless authentication
  - Password hashing with bcrypt
  - User profile management

- **Content Organisation**
  - Categories for topic organization
  - Threads within categories
  - Nested replies to threads

- **API Design**
  - RESTful API architecture
  - Clean separation of public/protected routes
  - Proper error handling and logging

- **Security**
  - Input validation
  - Secure password management
  - Protected routes with middleware
  - CSRF protection

## Technology Stack

- **Language:** Go 1.23.5
- **Web Framework:** Gin
- **ORM:** GORM
- **Database:** SQLite (easily adaptable to PostgreSQL/MySQL)
- **Authentication:** JWT (JSON Web Tokens)
- **Logging:** Logrus

## Getting Started

### Prerequisites
- Go 1.16 or higher
- Git

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/goforum.git
   cd goforum
   ```

2. Install dependencies
   ```bash
   go mod download
   ```

3. Set environment variables
   ```bash
   export JWT_SECRET=your_secure_jwt_secret
   export LOG_LEVEL=debug  # Options: debug, info, warn, error
   ```

4. Run the application
   ```bash
   go run ./backend/main.go
   ```

The server will start on port 8080 by default.

### Configuration

Environment variables:
- `JWT_SECRET` - Secret key for JWT signing
- `LOG_LEVEL` - Logging level (debug, info, warn, error)
- `GO_ENV` - Environment (development, production)

### Common Tasks

- Generate a secure JWT secret:
  ```bash
  openssl rand -hex 32
  ```

- Format all code:
  ```bash
  go fmt ./...
  ```

## Security Considerations

- JWT tokens expire after 8 hours
- Passwords are securely hashed using bcrypt
- Input validation is performed on all user inputs
- HTTP-only cookies are used to store tokens

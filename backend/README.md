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

- **Language:** Go 1.x
- **Web Framework:** Gin
- **ORM:** GORM
- **Database:** SQLite (easily adaptable to PostgreSQL/MySQL)
- **Authentication:** JWT (JSON Web Tokens)
- **Logging:** Logrus

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate and receive JWT

### Public Endpoints
- `GET /api/categories` - List all categories
- `GET /api/threads` - List threads (filter by category_id)
- `GET /api/threads/:id` - Get a specific thread
- `GET /api/threads/:id/replies` - Get replies for a thread

### Protected Endpoints
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update current user profile
- `POST /api/categories` - Create a new category
- `PUT /api/categories/:id` - Update a category
- `DELETE /api/categories/:id` - Delete a category
- `POST /api/threads` - Create a new thread
- `PUT /api/threads/:id` - Update a thread
- `DELETE /api/threads/:id` - Delete a thread
- `POST /api/threads/:id/replies` - Post a reply
- `PUT /api/threads/:id/replies/:replyId` - Update a reply
- `DELETE /api/threads/:id/replies/:replyId` - Delete a reply

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

## Project Structure

```
backend/
├── internal/
│   ├── constants/     - Application constants
│   ├── handlers/      - Request handlers
│   ├── middleware/    - Custom middleware
│   ├── models/        - Data models and DTOs
│   └── utils/         - Utility functions
└── main.go            - Application entry point
```

## Development

### Testing

Run the test suite:
```bash
go test ./...
```

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

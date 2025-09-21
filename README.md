# User Management Rails Application

A secure, production-ready user management system built with Ruby on Rails, featuring comprehensive protection against SQL injection, JavaScript injection, and XSS attacks.

## 🚀 Features

### Core Functionality
- **User Management**: Create, read, update, and delete users
- **Form Validation**: Client-side and server-side validation
- **Responsive Design**: Modern UI with Tailwind CSS
- **JSON API**: RESTful API endpoints for programmatic access

### Security Features
- **SQL Injection Protection**: Multi-layer defense against SQL injection attacks
- **JavaScript Injection Protection**: Comprehensive XSS and script injection prevention
- **Input Sanitization**: Automatic cleaning and normalization of user input
- **Strong Parameters**: Rails strong parameters for secure data handling
- **Email Validation**: Strict email format validation with proper domain requirements
- **Character Filtering**: Only allows safe characters in name fields

## 📋 User Model

The User model contains the following fields:
- `first_name` (required, max 64 characters, letters/spaces/hyphens/apostrophes only)
- `last_name` (required, max 64 characters, letters/spaces/hyphens/apostrophes only)
- `email` (required, max 64 characters, valid email format, unique)
- `created_at` (automatic timestamp)
- `updated_at` (automatic timestamp)

## 🛡️ Security Implementation

### SQL Injection Protection
- **Keyword Detection**: Blocks SQL keywords when used in malicious context
- **Pattern Matching**: Detects complex SQL injection patterns
- **Context Awareness**: Allows legitimate names while blocking attacks
- **Examples of Blocked Attacks**:
  - `DROP TABLE users`
  - `SELECT * FROM users`
  - `'; DROP TABLE users; --`
  - `UNION SELECT * FROM users`

### JavaScript Injection Protection
- **Event Handler Blocking**: Prevents all JavaScript event handlers
- **Script Tag Detection**: Blocks HTML script tags and JavaScript code
- **Protocol Filtering**: Prevents `javascript:`, `vbscript:`, and `data:` protocols
- **Context-Sensitive Keywords**: Blocks HTML/JS keywords only in malicious context
- **Examples of Blocked Attacks**:
  - `<script>alert("XSS")</script>`
  - `javascript:alert("XSS")`
  - `onload=alert("XSS")`
  - `data:text/html,<script>alert("XSS")</script>`

### Input Validation
- **Character Filtering**: Only allows letters, spaces, hyphens, and apostrophes
- **Length Limits**: Enforces maximum character limits
- **Email Validation**: Strict email format with proper domain validation
- **Real-time Validation**: Client-side validation with immediate feedback

## 🏗️ Architecture

### Models
- `User`: Main user model with comprehensive validations

### Controllers
- `UsersController`: Handles CRUD operations with sanitization

### Views
- Form-based interface with real-time validation
- JSON API responses for programmatic access

### JavaScript
- Real-time form validation
- Enhanced user experience with immediate feedback

## 🚦 Getting Started

### Prerequisites
- Ruby 3.4.5 or higher
- Rails 8.0.2 or higher
- PostgreSQL database

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd user-management-rails
   ```

2. **Install dependencies**
   ```bash
   bundle install
   ```

3. **Setup database**
   ```bash
   rails db:create
   rails db:migrate
   ```

4. **Start the server**
   ```bash
   rails server
   ```

5. **Access the application**
   - Web Interface: http://localhost:3000
   - API Endpoints: http://localhost:3000/users.json

## 📚 API Endpoints

### Users
- `GET /users` - List all users
- `GET /users/:id` - Show specific user
- `POST /users` - Create new user
- `PATCH/PUT /users/:id` - Update user
- `DELETE /users/:id` - Delete user

### JSON API
All endpoints support JSON format:
- `GET /users.json` - List users in JSON format
- `GET /users/:id.json` - Show user in JSON format
- `POST /users.json` - Create user via JSON
- `PATCH/PUT /users/:id.json` - Update user via JSON
- `DELETE /users/:id.json` - Delete user via JSON

## 🧪 Testing

Run the test suite:
```bash
rails test
```

The application includes comprehensive tests for:
- Controller actions
- Model validations
- Security features
- API endpoints

## 🔒 Security Considerations

### What's Protected
- ✅ SQL injection attacks
- ✅ JavaScript injection attacks
- ✅ XSS (Cross-Site Scripting) attacks
- ✅ HTML injection
- ✅ Script tag injection
- ✅ Event handler injection
- ✅ Protocol-based attacks

### What's Allowed
- ✅ Legitimate names with hyphens and apostrophes (e.g., "Jean-Pierre", "O'Connor")
- ✅ International names
- ✅ HTML element names as standalone names (e.g., "Script", "Table", "Canvas")
- ✅ Valid email addresses

## 📝 Important Notes

### User Controls
**Note**: This application does not include user authentication, authorization, or access controls. The system was designed as a basic user management interface without these features as they were not specified in the requirements. If user controls are needed, consider adding:

- User authentication (e.g., Devise gem)
- Role-based access control
- Session management
- Password requirements
- User permissions
- Admin interfaces

### Security Model
The current security model focuses on:
- Input validation and sanitization
- Protection against injection attacks
- Data integrity
- Form security

For production use, additional security measures should be considered:
- HTTPS enforcement
- CSRF protection (already included in Rails)
- Rate limiting
- Input logging and monitoring
- Security headers

## 🛠️ Development

### Code Quality
- RuboCop for Ruby code style
- ESLint for JavaScript code style
- Comprehensive test coverage
- Security-focused development practices

### Database
- PostgreSQL for production-ready data storage
- Proper indexing on email field for performance
- Migration-based schema management

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📞 Support

For questions or issues, please open an issue in the repository or contact the development team.

---

**Security Notice**: This application implements comprehensive security measures, but security is an ongoing process. Regular security audits and updates are recommended for production environments.
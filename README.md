## Table of Contents

1. [Controllers](#controllers)
   - [AuthController](#authcontroller)
   - [UserController](#usercontroller)
2. [Services](#services)
   - [AuthService](#authservice)
   - [UserService](#userservice)

# Controllers

## AuthController(`@Controller('auth')`)

- This controller handles endpoints for the `auth` path. This means all endpoint URLs start with `/auth`.
- Endpoints:
  - `@Post('login')`: Handles user login. It accepts login data (email and password) using `LoginDto` and processes the login through the `AuthService`.
  - `@Post('register')`: Handles user registration. It accepts user data from the request body using `CreateUserDto` and creates a user through the `UserService`.
  - `@Post('refresh')`: Handles token refresh. It secures the request using the `RefreshJwtGuard`, and receives user information from the request to refresh the token through the `AuthService`.

## UserController(`@Controller('user')`)

- This controller handles endpoints for the `user` path, meaning all endpoint URLs it handles start with `/user`.
- Endpoint:
  `@Get(':id')`: Retrieves details of a specific user by their name. It's protected by the `JwtGuard` to ensure that only authenticated requests can access this endpoint.

# Services

## AuthService

### Purpose

- The `AuthService` provides authentication-related functionalities, including user login and token refresh operations.

### Key Methods

- `login(dto: LoginDto)`: Handles user login, generates JWT tokens (a sign token and a renew token), and logs the event.
- `validateUser(dto: LoginDto)`: Validates a user's credentials (email and password) against stored records. Throws an UnauthorizedException if credentials are invalid.
- `refreshToken(user)`: Refreshes a user's authentication tokens, generating new sign and renew tokens, and logs the token refresh activity.

### Security & Authentication

- Utilizes `bcryptjs` for password comparison during user validation, ensuring secure password checking.
- Uses `@nestjs/jwt`'s `JwtService` for JWT token generation, supporting both access (sign token) and refresh (renew token) mechanisms with different expiration times.

### JWT Token Details

- `Sign Token`: Short-lived access token with a default expiration of 180 seconds.
- `Renew Token`: Longer-lived token intended for refreshing the sign token, with a default expiration of 1 day.

### Return Values

- Upon successful login, returns an object containing user details (email and name) and the generated backend tokens (sign and renew tokens).
- The `refreshToken` method returns an object with the new backend tokens.

## UserService

### Purpose

- The `UserService` manages user-related functionalities, including creating new users and finding users by email or name within a database.

### Key Methods

- `create(dto: CreateUserDto)`: Creates a new user after checking if the user already exists by email to prevent duplicates, hashes the user's password, and logs the creation.
- `findByEmail(email: string)`: Retrieves a user by their email address, logs the search operation, and handles user not found scenarios.
- `findByName(name: string)`: Searches for a user by their name, logs the operation, and addresses cases where the user is not found.

### Security & Data Management

- Employs `bcryptjs` for hashing passwords before storing them in the database, ensuring that user passwords are securely managed.
- Uses Mongoose models for database operations, allowing for structured data access and manipulation within a MongoDB database.

### Return Values

- The `create` method returns the created user's information excluding the password, ensuring sensitive information is not exposed.
- Both `findByEmail` and `findByName` return the found user object or `null` if no user is found, facilitating error handling and further processing by calling services.

Table of Contents
Introduction

Purpose of the Documentation
Overview of the Backend Architecture
Key Technologies Used (e.g., Node.js, Django, etc.)
Prerequisites for Understanding This Documentation
System Architecture

High-Level Architecture Diagram
Component Diagram with Relationships and Flows
Explanation of Communication Protocols (e.g., REST, GraphQL, WebSocket)
Tools: Lucidchart, Draw.io, or Visio for diagrams.

Overview of JWT (JSON Web Tokens)
Authorization Flow with Diagrams
Token Expiration and Refresh Mechanisms
Tools: Postman for testing authentication endpoints, Swagger for API documentation.

Database Management

Database Schema Overview (ERD Diagrams)
Data Storage for Images
Explanation of Storing Images in the Database vs. File System
Reference to any File Storage Services (e.g., AWS S3, Google Cloud Storage)
Tools: DB Designer, PgAdmin, or MySQL Workbench.

Security Features

Password Hashing and Salting Process
Explanation of Hashing Algorithms (e.g., bcrypt, Argon2)
Secure Storage of Sensitive Information
Rate Limiting and Protection Against Brute Force Attacks
Tools: OWASP Cheat Sheets, Burp Suite for security testing.

Image Handling

Explanation of Image Upload and Retrieval
Steps for Processing Images (e.g., Resizing, Compression)
Storage Mechanism (Database or External File Storage)
Tools: Sharp (for image processing in Node.js), ImageMagick.

Email Services

Email Sending Mechanism
Libraries/Services Used (e.g., Nodemailer, SendGrid)
Example Code Snippet for Sending Emails
Configuration of SMTP Servers
Tools: Mailtrap for testing emails, SendGrid for production services.

Deployment Process

Setting Up the Server Environment
Using Docker for Containerization
CI/CD Pipeline Overview
Environment Variables and Secrets Management
Tools: Docker Compose, GitHub Actions or Jenkins for CI/CD.

API Documentation

API Endpoints (Routes, Methods, and Payloads)
Example Requests and Responses
Error Codes and Their Meanings
Tools: Swagger UI, Postman, or Redoc.

Monitoring and Logging

Logging Mechanism (e.g., Winston, Morgan)
Application Performance Monitoring (e.g., New Relic, Datadog)
Error Tracking Tools (e.g., Sentry)
Tools: LogDNA, Elastic Stack.

FAQ and Troubleshooting

Common Issues and Solutions
Tips for Debugging
Where to Find Support (e.g., Official Documentation, Community Forums)
Appendices

Glossary of Terms
Links to Resources and References
Additional Diagrams or Supporting Information

# 3. Authentication and Authorization

### Overview
The authentication and authorization layer is designed to:

* Secure user access using a JWT-based mechanism.
* Register new users with encrypted passwords and role assignments.
* Validate login credentials and issue JWTs with an expiration time.
* Authenticate and authorize API requests using a custom JWT filter.

### Registration
The registration process allows new users to create an account. The system ensures:

* Email Uniqueness: Checks whether the provided email already exists in the database.
* Password Generation: A random password is generated, encrypted, and sent to the user via email.
* Role Assignment: New users are assigned the default role (ROLE_USER).
* Email Notification: Sends an email with the login credentials.

#### Endpoint:
POST /auth/register

#### Request Body:
The RegisterDTO contains:
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com"
}
```

#### Response:

* Success: A message indicating the account was created and an email was sent.
* Failure: An error if the email is already registered or if email delivery fails.
#### Code Explanation:

* The register() method in AuthenticationController:
    - Verifies email uniqueness via userRepository. 
    - Calls AuthenticationService.register() to:
      - Create and persist the User.
      - Send the login credentials via email.
      - Handles email-related exceptions (MessagingException).
```java
if (userRepository.findByEmail(registerDTO.getEmail()).isPresent())
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("An account with this email already exists");

User user = authenticationService.register(registerDTO);
return ResponseEntity.ok("Your account was created! Check your email");
```

### Login
The login process validates user credentials and generates a JWT for authenticated access.

#### Endpoint:
POST /auth/login

#### Request Body:
The LoginDTO contains:
```json
{
  "email": "john.doe@example.com",
  "password": "password123"
}
```

#### Response:

- Success: Success: Returns a LoginResponse with the JWT, expiration time, and user details.
- Failure: Returns an error if the credentials are invalid.

Code Explanation:

- The login() method in AuthenticationController:
    - Authenticates the user using AuthenticationManager.
    - Generates a JWT using JwtService.generateToken().

#### Code Snippet:

```java
Authentication authentication = authenticationManager.authenticate(
    new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword())
);
String jwtToken = jwtService.generateToken(user);
return ResponseEntity.ok(new LoginResponse(jwtToken, user.getFirstName(), user.getLastName(), user.isNew()));
```

### JWT-Based Authentication
JWT (JSON Web Token) is used for secure communication between the client and server.

#### Features:
* Token Generation: The JwtService generates a JWT containing the username, issued time, and expiration time, signed using an HMAC-SHA256 key.
* Token Validation: Validates the token signature and expiration time before granting access to protected resources.
* Middleware Enforcement: A JwtAuthenticationFilter intercepts each request to ensure that valid tokens are included.
#### Token Structure
* Header: Algorithm & Token Type
* Payload: Claims (username, roles, issued at, expiry)
* Signature: Verifies integrity using a secret key.
#### Token Generation
The JwtService.generateToken() method creates tokens using:

* Claims for additional metadata.
* A subject (username).
* Expiration settings based on jwtExpiration.
```java
public String generateToken(UserDetails userDetails) {
    return buildToken(new HashMap<>(), userDetails, jwtExpiration);
}
private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expirationTime) {
    return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
}
```
#### Token Validation
The JwtService.isTokenValid() method ensures the token is valid for the given user and has not expired.

### JWT Authorization Filter
The JwtAuthenticationFilter ensures that each incoming request contains a valid JWT for secured endpoints.

#### Workflow:

1. Extracts the token from the Authorization header.
2. Validates the token's signature and expiration.
3. Loads the UserDetails and sets it in the security context.
#### Code Snippet:
```java
final String jwt = authHeader.substring(7);
final String userEmail = jwtService.extractUsername(jwt);
if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
    if (jwtService.isTokenValid(jwt, userDetails)) {
        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}
```

### Error Handling
The JwtAuthenticationFilter handles exceptions using HandlerExceptionResolver to provide meaningful error messages without exposing sensitive information.

#### Code Snippet:
```java
catch (Exception e) {
    handlerExceptionResolver.resolveException(request, response, null, e);
}
```

### Security Highlights
* Password Encryption: Passwords are hashed using PasswordEncoder (e.g., bcrypt).
* Role-Based Authorization: Roles (ROLE_USER) are assigned and enforced for access control.
* Secure Communication: Tokens are signed and verified with a secret key.

### Key Dependencies
* Spring Security: For authentication and role-based access control.
* JJWT (io.jsonwebtoken): For JWT generation and validation.
* EmailSender: For sending account-related emails.

# 5. Security Features

### Overview 
The application leverages modern security practices to protect sensitive data and ensure secure communication between the client and the server. The key security features include:
* Stateless authentication using JWT.
* Secure password hashing.
* Role-based access control.
* Cross-Origin Resource Sharing (CORS) configuration for controlled client-server communication.
* Protection against CSRF (Cross-Site Request Forgery) attacks.

### Authentication and Authorization
The backend uses Spring Security to manage authentication and authorization:
* Authentication Provider: Validates user credentials via the AuthenticationManager and delegates authentication tasks.
* JWT Authentication Filter: Ensures secure access to protected resources by validating tokens.
* Role-Based Access Control: Implements roles (e.g., ROLE_USER) to restrict access to specific endpoints.

#### Configuration:

* Authentication is stateless, meaning no session is maintained on the server. Instead, JWTs are used for client authentication.
* Authorization is enforced at the endpoint level:
  - Public endpoints: /auth/** (e.g., login, registration).
  - Protected endpoints: Require a valid JWT.
#### Code Snippet:
```java
http.csrf(AbstractHttpConfigurer::disable)
    .cors(Customizer.withDefaults())
    .authorizeHttpRequests(auth ->
        auth.requestMatchers("/auth/**").permitAll()
            .anyRequest().authenticated()
    )
    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .authenticationProvider(authenticationProvider)
    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
```

### Password Security
The system ensures secure password storage and validation by using:
* Password Hashing: Passwords are hashed using PasswordEncoder (e.g., bcrypt), which securely encrypts passwords before saving them in the database.
* Salting: Each password is uniquely salted to prevent attacks using precomputed hash databases (rainbow tables).

#### Code Snippet:
```java
String password = PasswordService.generatePassword();
user.setPassword(passwordEncoder.encode(password));
```

### Cross-Origin Resource Sharing (CORS)
CORS settings are configured to allow specific client requests to access server resources securely:
* Allows requests from any origin (*), which can be restricted for production environments.
* Permits only specific HTTP methods (e.g., GET, POST, PUT, DELETE).
* Supports Authorization and Content-Type headers for secure communication.

#### Code Snippet:
```java
CorsConfiguration configuration = new CorsConfiguration();
configuration.addAllowedOriginPattern("*");
configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
configuration.setAllowCredentials(true);
```
This configuration is registered for all endpoints using a CorsConfigurationSource bean.

### Stateless Authentication
The application follows a stateless authentication model where:
1. JWT-Based Authentication:
* Each request must include a valid JWT in the Authorization header (Bearer <token>).
* The JwtAuthenticationFilter validates the token and sets the authentication context.
2. Session Management:
* SessionCreationPolicy.STATELESS ensures no session is stored on the server.
```java
http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
```

### CSRF Protection
CSRF attacks are mitigated by disabling CSRF protection for stateless API endpoints. This is safe because the application does not rely on cookies for authentication.

#### Code Snippet:
```java
http.csrf(AbstractHttpConfigurer::disable);
```

### Error Handling
To ensure a secure and user-friendly experience, the JwtAuthenticationFilter handles errors during token validation by using HandlerExceptionResolver. This prevents exposure of sensitive information.

#### Code Snippet:
```java
catch (Exception e) {
    handlerExceptionResolver.resolveException(request, response, null, e);
}
```

### Security Best Practices
* Use Strong Secrets: The JWT secret key is configured securely via application properties.
* Token Expiration: JWTs are issued with an expiration time to limit token misuse.
* Limit CORS Access: While development allows *, production environments should specify trusted origins.
* Secure Passwords: Use a high-strength hashing algorithm like bcrypt or Argon2.
* Monitor for Vulnerabilities: Regularly audit dependencies for security vulnerabilities.

### Key Dependencies
* Spring Security: Provides the foundation for authentication and authorization.
* JwtAuthenticationFilter: Custom filter for validating JWTs.
* PasswordEncoder: Hashes and validates passwords.
* CORS Configuration: Manages client-server communication securely.

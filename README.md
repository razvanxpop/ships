# Table of Contents
* [**1. Introduction**](#1-introduction)
* [**2. System Architecture**](#2-system-architecture)
* [**3. Authentication and Authorization**](#3-authentication-and-authorization)
* [**4. Database Management**](#4-database-management)
* [**5. Security Features**](#5-security-features)
* [**6. Image Handling**](#6-image-handling)
* [**7. Email Services**](#7-email-services)
* [**8. API Documentation**](#8-api-documentation)
* [**9. Troubleshooting**](#9-faq-and-troubleshooting)
* [**10. Appendices**](#10-appendices)


# 1. Introduction
This section introduces the documentation for the backend server of the client-server application. It serves as a guide for new developers joining the project, providing an overview of the application's architecture, technologies, and prerequisites. The goal is to reduce onboarding time, allowing new contributors to quickly understand, adapt, and contribute effectively to the development of the application.

### Purpose
The purpose of this documentation is to:
* Provide a clear and detailed understanding of the backend server.
* Minimize the onboarding time for new developers by offering structured information on the architecture, key processes, and implementation details.
* Enable efficient feature development and debugging by equipping developers with the necessary context and tools.

### Overview of the Architecture
The application follows a Model-View-Controller (MVC) design pattern with a layered architecture. Each layer has a specific responsibility, ensuring modularity, scalability, and maintainability:

**Controller Layer:**
* Handles HTTP requests and responses.
* Delegates business logic to the service layer.
**Service Layer:**
* Implements business logic.
* Interacts with the data layer and other external systems.
**Repository Layer:**
* Manages data access and communication with the database.
**Security Layer:**
* Manages authentication, authorization, and security configurations.
**Utilities:**
* Handles reusable components like email sending, JWT generation, and other helpers.

The **layered architecture** ensures separation of concerns, making the codebase more maintainable and easier to debug.

### Key Technologies
The backend server is built using the following technologies:

* Java 21:
    * Modern Java features are utilized to ensure efficient and clean code.
* Spring Boot:
  * A framework for building Java-based applications.
  * Provides features for dependency injection, security, REST APIs, and more. 
* Docker:
  * Used to containerize the application for consistent deployment across environments.
  * Simplifies environment setup and dependency management.

### Prerequisites
Before diving into this documentation, it is recommended that readers have a basic understanding of:
* Java: Familiarity with Java programming, including OOP principles and syntax.
* Spring Boot: Knowledge of Spring Boot fundamentals such as dependency injection, controllers, and repositories.

For developers who are not familiar with Spring Boot, it is suggested to explore its official documentation to gain foundational knowledge.

###  Additional Notes
This documentation assumes familiarity with the general software development lifecycle (SDLC) and tools like Git for version control. If there are team-specific conventions (e.g., branching strategies, code review policies), these should be covered in a separate onboarding guide.

# 2. System Architecture
This section provides a detailed description of the backend server's system architecture. It covers the architectural pattern, main components, and how they interact to ensure scalability, modularity, and maintainability. It also summarizes key packages, including their roles in the overall architecture.

### Architectural Overview
The backend server follows a Model-View-Controller (MVC) design pattern with a layered architecture to ensure clear separation of concerns and reusable components.

### Layers in the Architecture:
1. Controller Layer:
* Handles HTTP requests and responses.
* Delegates business logic execution to the service layer.
* Includes classes like AuthenticationController, PetController, UserController, and VeterinaryAppointmentController.
2. Service Layer:
* Contains the business logic and orchestrates interactions between the controller and repository layers.
* Includes services such as AuthenticationService, PetService, UserService, and VeterinaryAppointmentService.
3. Repository Layer:
* Directly interacts with the database to perform CRUD operations.
* Manages data persistence and retrieval.
* Includes repositories like UserRepository, PetRepository, RoleRepository, and VeterinaryAppointmentRepository.
4. Security Layer:
* Manages authentication and authorization using JWT-based authentication.
* Implements custom filters, exception handling, and CORS policies.
5. Utility Layer:
* Provides reusable helper components such as the PasswordService, MapperUtil, and the email services.

### Core Components
**2.1 Controller Layer**
Handles HTTP requests and maps them to the corresponding service methods.
* **AuthenticationController:**
    * Handles user registration (/auth/register) and login (/auth/login).
    * Ensures secure authentication using JWT tokens generated by the JwtService.
* **PetController**:
  * Manages endpoints for CRUD operations on pets (/pets).
  * Ensures only authorized users can access and modify their pets.
  * Example endpoints:
    * GET /pets/all: Retrieves all pets owned by the authenticated user.
    * POST /pets/add: Creates a new pet entry for the authenticated user.
* **UserController**:
  * Provides endpoints for user-related operations (/users).
  * Allows users to update their profiles and view their pets.
* **VeterinaryAppointmentController**:
  * Manages appointments for pets (/api/veterinary-appointments).
  * Allows users to schedule, update, and cancel appointments.
  
2.2 **Service** Layer
Implements business logic and interacts with repositories for data persistence.

* **AuthenticationService:**
  * Handles user registration, including password hashing and email notifications.
  * Authenticates users and retrieves their details.
  * Authenticates users using the AuthenticationManager.
* **PetService:**
  * Manages the creation, retrieval, updating, and deletion of pet records.
  * Ensures data integrity and access control by associating pets with their owners.
* **UserService**:
  * Manages user operations, including finding users by email or ID, adding pets for users, and updating user records.
  * Enforces role-based access control for user actions.
* **VeterinaryAppointmentService**:
  * Handles appointment scheduling, updates, and cancellations.
  * Ensures appointments are associated with the correct pet and user.
  * Sends appointment notifications to users.
  
**2.3 Repository Layer**
Provides data access logic to the services.
* **UserRepository**:
  * Handles database operations related to users, such as finding users by email or ID.
* **PetRepository**:
  * Manages pet-related database operations, such as finding pets by their owner or ID.
* **RoleRepository**:
  * Handles CRUD operations for user roles.
* **VeterinaryAppointmentRepository**:
  * Manages veterinary appointment records, including CRUD operations and queries.
  
**2.4 Security Layer**
Implements authentication and authorization using Spring Security.

* **JwtAuthenticationFilter:**
  * Validates JWT tokens and sets the security context for authenticated requests.
* **SecurityConfiguration:**
  * Configures authentication, authorization, CORS, and session management.
    * Configures HTTP security settings, including:
        * Disabling CSRF protection for stateless authentication.
        * Permitting public endpoints like /auth/** for registration and login.
        * Enforcing authentication for all other endpoints.
      
**2.5 Utility Layer**
Supports the system with reusable helpers and utility classes.

* **PasswordService**:
    * Generates strong passwords with uppercase, lowercase, digits, and special characters.
    * Validates password strength during creation.
* **EmailSender**:
  * Sends transactional emails such as account creation notifications and appointment reminders.
  * Uses Thymeleaf templates for HTML email generation.
* **MapperUtil**:
  * Provides mapping utilities for converting entities to DTOs and vice versa.
  * Ensures clean separation between entity and DTO objects.

### Component Relationships
A Component Diagram illustrates how the main components interact. Below is a textual description of the relationships:

1. Controller Layer:
* Invokes the Service Layer to handle business logic.
* Receives input (e.g., JSON data) from HTTP requests and sends responses.
2. Service Layer:
* Calls the Repository Layer for database interactions.
* Delegates cross-cutting concerns (e.g., email sending, password generation) to Utility Layer components.
3. Repository Layer:
* Directly communicates with the database to store, retrieve, update, or delete data.
4. Security Layer:
* Ensures all incoming requests pass through the JwtAuthenticationFilter for validation before reaching controllers.
* Protects resources based on roles and permissions.
5. Utility Layer:
* Provides reusable utilities to the Service Layer for tasks like password hashing and email formatting.

### Layered Interaction Example
Here’s an example of how layers interact during a user registration workflow:

1. Request: A user submits their registration data to the POST /auth/register endpoint.
2. Controller Layer: The AuthenticationController receives the request and delegates the logic to the AuthenticationService.
3. Service Layer:
   * The AuthenticationService:
     1. Validates the input.
     2. Creates a hashed password using PasswordService.
     3. Assigns the default ROLE_USER to the new user.
     4. Saves the user to the database via UserRepository.
     5. Sends a confirmation email using the EmailSender.
4. Repository Layer: The UserRepository saves the new user record in the database.
5. Utility Layer:
   * The PasswordService generates a secure password.
   * The EmailSender sends the account creation email using a Thymeleaf template.

### UML Diagram
<img src="./images/uml-diagram.png" alt="Uml Diagram" height="256" width="256">

### Component Diagram
<img src="./images/component-diagram.png" alt="Component Diagram" height="128" width="100">

# 3. Authentication and Authorization
This section describes the authentication and authorization processes implemented in the backend server for the client-server application. It includes an overview of user registration, login functionality, and JWT (JSON Web Token) usage for secure authentication.

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

# 4. Database Management
The backend uses PostgreSQL as the database management system, running in a Dockerized environment. PostgreSQL is selected for its robust handling of relational data, support for advanced data types (e.g., JSON, arrays, and large objects), and scalability.

### Key Highlights:
* Relational Database: Follows normalized schema design to reduce redundancy and improve consistency.
* Entity Relationships: Tables are structured to represent real-world relationships, such as users owning pets and scheduling veterinary appointments.
* Large Object Storage: Images are stored in the database using PostgreSQL's OID (Object Identifier) for handling binary data efficiently.

### Data Storage Practices
**2.1 Password Management**
* Passwords are hashed and salted before being stored in the database.
* The application uses PasswordEncoder (e.g., bcrypt) to hash passwords, making them resistant to brute-force and rainbow table attacks.
* Example:
  ```json
  String password = PasswordService.generatePassword();
  user.setPassword(passwordEncoder.encode(password));
  ```

**2.2 Image Storage**
* User profile images are stored as binary data using PostgreSQL's OID (Object Identifier) type.
* The images are first converted into Base64 strings when being sent to or retrieved from the database. This ensures compatibility with JSON-based APIs.
* Conversion Process:
  * To Base64: For API responses, image data is encoded into a Base64 string:
    ```json
    String base64Image = Base64.getEncoder().encodeToString(user.getImageData());
    ```
  * From Base64: For saving in the database, the image is stored as OID.

**2.3 Relationships and Constraints**
* Users and Roles: One-to-Many relationship.
  * A user can have multiple roles (e.g., ROLE_USER, ROLE_ADMIN).
* Users and Pets: One-to-Many relationship.
  * Each user can own multiple pets.
* Pets and Veterinary Appointments: Many-to-One relationship.
  * A pet can have multiple veterinary appointments, but each appointment is linked to one pet.

### Schema Design
<img src="./images/erd-diagram.jpg" alt="ERD Diagram" height="128" width="128">

### Query Optimization
The application uses JPA (Java Persistence API) for interacting with the database. JPA offers the following advantages:
* Lazy Loading: Relationships are loaded only when needed, reducing unnecessary data retrieval.
* Custom Queries: For complex queries, custom methods are defined in repositories. Example:
  ```java
  @Query("SELECT p FROM Pet p WHERE p.owner.email = :email")
  List<Pet> findPetsByOwnerEmail(@Param("email") String email);
  ```

### Dockerized PostgreSQL
The application uses a Dockerized PostgreSQL instance, ensuring consistent environments across development, testing, and production.
**Key Configuration:**
* The compose.yml file defines the PostgreSQL service
  ```java
  services:
  postgres:
    image: 'postgres:latest'
    environment:
      POSTGRES_USER: 'pawpaw_user'
      POSTGRES_PASSWORD: 'pawpaw_password'
      POSTGRES_DB: 'pawpal_db'
    ports:
      - '5435:5432'
  ```
**Advantages**:
* Easy environment replication.
* Persistent volume for database data.

### Example Workflow
User Registration with Profile Image:
1. Input: A user submits their details and an optional profile image.
2. Processing:
   * Image data is received as a Base64 string.
   * Converted to binary and stored in the database as OID.
   * Password is hashed and stored securely.
3. Storage: The user and their data (including the image) are saved in the Users table.
4. Retrieval: When retrieving the user data, the image binary is converted back to a Base64 string and included in the API response.

# 5. Security Features
This section outlines the security features implemented in the backend server to ensure secure access and data protection. It includes configurations for authentication, authorization, password security, and CORS (Cross-Origin Resource Sharing) policy enforcement.

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

# 6. Image Handling
This section explains how the backend server manages user profile images, including how they are processed, stored, and retrieved. The system leverages PostgreSQL for storage and follows best practices for handling binary data.

### Overview
User profile images are an optional feature that allows users to personalize their accounts. The backend supports image upload, storage, and retrieval in a secure and efficient manner.
**Key Features:**
* Image Upload: Images are received as Base64-encoded strings in API requests.
* Database Storage: Images are stored in the database as binary data using PostgreSQL's OID (Object Identifier) type.
* Image Retrieval: Images are converted back to Base64 strings and sent to clients via API responses.

### Image Handling Workflow
**2.1 Uploading Images**
1. Input: The user uploads a profile image in Base64 format as part of their account details.
2. Processing:
   * The Base64 string is decoded into binary data.
   * The binary data is stored in the database under the imageData column in the Users table.
   * The MIME type of the image (e.g., image/png) is stored in the imageType column for easy retrieval.

**Code Snippet**:
```java
public static UserDTO toUserDTO(User user) {
    String base64Image = "";
    if (user.getImageData() != null) {
        base64Image = Base64.getEncoder().encodeToString(user.getImageData());
    }
    return new UserDTO(user.getId(), user.getFirstName(), user.getLastName(), user.getEmail(), 
                       user.getPassword(), user.isNew(), user.getRoles(), petsDTO, base64Image, 
                       user.getImageType());
}
```

**2.2 Retrieving Images**
1. Fetching:
  * When a user's data is retrieved, the imageData column is queried.
  * The binary image data is converted to a Base64 string.
2. Response:
  * The API includes the Base64 string in the image field of the response.
  * The imageType field specifies the MIME type for rendering.

**Example API Response:**
```json
{
  "id": 1,
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg...",
  "imageType": "image/png"
}
```

**2.3 Deleting or Updating Images**
* When a user's profile image is updated or removed:
  * The existing binary data in the database is replaced or deleted.
  * Updates are seamless since the image is referenced by the user's id.

### Storage Details
**Database Storage**
* Column: The imageData column in the Users table stores binary data.
* Type: PostgreSQL's OID (Object Identifier) type is used for large binary objects.
* Advantages:
  * Efficient storage for binary data.
  * Simplified management of associated metadata (e.g., MIME type).
**Best Practices for Image Storage:**
1. Keep Images Optional:
  Not all users will upload images, so the imageData column allows NULL values.
2. Store Metadata:
  Save the image MIME type (image/png, image/jpeg) in a separate column for compatibility.
3. Optimize Retrieval:
  Convert binary data to Base64 only when needed to minimize overhead.

### Security and Validation
1. File Type Validation:
  Ensure only valid image types (e.g., png, jpeg) are accepted.
  Reject unsupported or potentially malicious files.
2. Size Restrictions:
  Enforce maximum file size limits to prevent excessive database usage.
  Example: Restrict image uploads to 5MB.
3. Base64 Encoding:
  Convert binary data to Base64 strings for compatibility with JSON-based APIs.
4. Environment-Specific Configurations:
  For production environments, consider offloading images to dedicated file storage services like AWS S3 or Google Cloud Storage for scalability.

### Example Workflow
Uploading a Profile Image:
1. Request: A user sends their profile image (in Base64 format) to the server via a POST request.
2. Processing:
  * Decode the Base64 string to binary.
  * Store the binary data in the imageData column.
  * Save the image MIME type in the imageType column.
3 . Response:
  * A confirmation message is sent to the user

# 7. Email Services
This section describes the email services implemented in the backend server. These services are designed to handle user communication, including account creation, appointment notifications, and reminders. The implementation ensures reliability, scalability, and customizability by leveraging HTML templates and Spring's email capabilities.

### Overview
The email service is responsible for:
* Sending transactional emails to users.
* Customizing emails using dynamic templates.
* Supporting HTML content for rich email formatting.
* Centralizing email-related operations within a reusable service.
The service uses:
* Spring JavaMailSender for email delivery.
* Thymeleaf Template Engine for HTML email generation.

### Key Features
1. HTML Email Support:
* Emails are sent with HTML content to provide a better user experience.
* Templates are dynamically populated with user-specific data.
2. Predefined Email Types:
* Account Creation Email: Sent when a new account is created.
* Appointment Notification Email: Sent when a new appointment is scheduled.
* Appointment Reminder Email: Sent as a reminder for upcoming appointments.
3. Reusable and Scalable Design:
* Centralized methods for sending emails.
* Templates stored separately for better management and customization.

### Service Methods
#### sendHTMLEmail
This is a generic method for sending HTML-based emails.
#### Parameters:
* to: Recipient's email address.
* subject: Subject of the email.
* body: HTML content of the email.
#### Workflow:
1. Creates a MIME message.
2. Configures sender, recipient, subject, and body.
3. Sends the email using JavaMailSender.

#### Code Snippet:
```java
public void sendHTMLEmail(String to, String subject, String body) throws MessagingException {
    MimeMessage mimeMessage = mailSender.createMimeMessage();
    MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

    mimeMessageHelper.setFrom("pawpal8787@gmail.com");
    mimeMessageHelper.setTo(to);
    mimeMessageHelper.setSubject(subject);
    mimeMessageHelper.setText(body, true);
    mailSender.send(mimeMessage);
}
```

#### sendMailForNewAccount
This method sends an email with account details when a new user registers.

#### Parameters:
* to: Recipient's email address.
* subject: Subject of the email.
* templateModel: Data to populate the email template (e.g., name, temporary password).
#### Workflow:
1. Loads the new_account.html template.
2. Populates the template with templateModel variables.
3. Sends the email using sendHTMLEmail.

#### Code Snippet:
```java
Context context = new Context();
context.setVariables(templateModel);
String html = templateEngine.process("new_account.html", context);
sendHTMLEmail(to, subject, html);
```

#### sendMailForNewAppointment
This method notifies users of newly scheduled appointments.
#### Parameters:
* Same as sendMailForNewAccount.
#### Workflow:
1. Loads the new_appointment.html template.
2. Populates the template with templateModel variables.
3. Sends the email.

#### Code Snippet:
```java
Context context = new Context();
context.setVariables(templateModel);
String html = templateEngine.process("new_appointment.html", context);
sendHTMLEmail(to, subject, html);
```

#### sendMailForAppointmentReminder
This method sends reminders for upcoming appointments.
#### Parameters:
* Same as sendMailForNewAccount.
#### Workflow:
1. Loads the appointment_reminder.html template.
2. Populates the template with templateModel variables.
3. Sends the email.

#### Code Snippet:
```java
Context context = new Context();
context.setVariables(templateModel);
String html = templateEngine.process("appointment_reminder.html", context);
sendHTMLEmail(to, subject, html);
```

### Dynamic Email Templates
The email service uses Thymeleaf templates to create dynamic and visually appealing emails. Each template is populated with user-specific data (e.g., name, password, appointment details).

#### Template Example(new_account.html):
```html
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to PawPal</title>
</head>
<body>
    <h1>Hello, [[${recipientName}]]!</h1>
    <p>Your account has been created successfully. Your temporary password is: <strong>[[${generatedPassword}]]</strong></p>
    <p>Please log in and change your password immediately.</p>
    <p>Regards,</p>
    <p>The PawPal Team</p>
</body>
</html>
```

### Configuration
#### JavaMailSender
The JavaMailSender bean is configured with the SMTP server details (e.g., Gmail, SendGrid). It handles email delivery.

#### SMTP Configuration:
* Host: SMTP server host (e.g., smtp.gmail.com).
* Port: SMTP port (e.g., 587).
* Authentication: Sender’s email and password.
* TLS/SSL: Ensures encrypted communication.

### Error Handling
All email-sending methods handle MessagingException, which may occur due to:
* Invalid recipient address.
* SMTP server issues.
* Network interruptions.
### Error Logging: Exceptions are logged to help diagnose email delivery issues.

### Security Considerations
1. Environment Variables:
* Store SMTP credentials (username, password) securely in environment variables or a secrets manager.
2. Rate Limiting:
* Configure rate limits for email sending to prevent abuse.
3. Email Spoofing Prevention:
* Use SPF, DKIM, and DMARC configurations to verify email authenticity.

### Scalability Recommendations
* Asynchronous Email Sending:
    - Use a task queue (e.g., RabbitMQ, Kafka) for processing email requests asynchronously.
* Batch Processing:
  - Group email notifications to reduce overhead.

# 8. API Documentation
This section provides a comprehensive overview of the API endpoints exposed by the backend server. Each endpoint is described with its HTTP method, path, request body, response format, status codes, and authorization requirements.

### Overview
The API is designed using REST principles and follows a modular structure. The primary resources exposed are:
* Authentication (/auth)
* Users (/users)
* Pets (/pets)
* Veterinary Appointments (/api/veterinary-appointments)

**Key Features:**
* JSON-based request and response formats.
* Authentication via JWT tokens.
* Role-based access control.

### Endpoints
**2.1 Authentication**
Handles user registration and login.
* POST /auth/register
    * Description: Creates a new user account.
      * Request Body:
          ```json
          {
            "firstName": "John",
            "lastName": "Doe",
            "email": "john.doe@example.com"
          }```
      * Response:
        * 200 OK: "Your account was created! Check your email."
        * 400 Bad Request: "An account with this email already exists
* POST /auth/login
  * Description: Authenticates a user and generates a JWT token.
    * Request Body:
      ```json
      {
      "email": "john.doe@example.com",
      "password": "password123"
      }
      ```
    * Response:
      * 200 OK: JWT token and user details.
      * 401 Unauthorized: Invalid credentials
      ```json
      {
      "token": "JWT_TOKEN",
      "firstName": "John",
      "lastName": "Doe",
      "newUser": false
      }
      ```

**2.2 Users**
Manages user operations.

* GET /users/all (Admin only)
  * Description: Retrives all users in the system.
  * Authorization: ROLE_ADMIN
  * Response:
    * 200 OK: List of users.
    * 204 No Content: No users found.
    * 403 Forbidden: Unauthorized access.
    * 500 Internal Server Error: Server error. 
    ```json
    [
      {
        "id": 1,
        "firstName": "Dan",
        "lastName": "Smith",
        "email": "dansmith@email.com",
        "password": "adasd!!@34213!!ds",
        "isNew": true,
        "roles": [], 
        "pets": [], 
        "image": "base64encodedimage",
        "imageType": "image/jpeg" 
      }
    ]
    ```

* POST /users/add (Admin only)
  * Description: Creates a new user.
  * Authorization: ROLE_ADMIN
  * Request Body:
    ```json
    {
      "firstName": "Dan",
      "lastName": "Smith",
      "email": "dansmith@email.com"
    }
    ```
  * Response:
    * 201 OK: "User created successfully."
    * 400 Bad Request: "Invalid request body."
    * 403 Forbidden: Unauthorized access.
    * 409 Conflict: "User already exists."
    * 500 Internal Server Error: Server
    ```json
    {
        "id": 1,
        "firstName": "Dan",
        "lastName": "Smith",
        "email": "dansmith@email.com",
        "password": "adasd!!@34213!!ds",
        "isNew": true,
        "roles": [], 
        "pets": [], 
        "image": "base64encodedimage",
        "imageType": "image/jpeg" 
      }
    ```

* POST /user/del/{userId}
  * Description: Deletes the user with the specified ID.
  * Authorization: ROLE_ADMIN
  * Response:
    * 204 No Content: User deleted successfully.
    * 403 Forbidden: Unauthorized access.
    * 404 Not Found: User not found.
    * 500 Internal Server Error: Server error.

* POST /users/reset (User only)
  * Description: Resets the user's password.
  * Authorization: ROLE_USER
  * Request Body:
    ```json
    {
      "password": "damkmdas!!@#!@3dasd"
    }
   ``` 
    * Response:
        * 200 OK: "Password reset successful."
        * 400 Bad Request: "Invalid request body."
        * 403 Forbidden: Unauthorized access.
        * 404 Not Found: "User not found."
        * 409 Conflict: "Password reset failed."
        * 500 Internal Server Error: Server error.

* GET /user/details
  * Description: Retrieves the details of the authenticated user.
  * Authorization: ROLE_USER
  * Response:
    * 200 OK: User details.
    * 403 Forbidden: Unauthorized access.
    * 404 Not Found: "User not found."
    * 500 Internal Server Error: Server error.
    ```json
    {
      "firstName": 1,
      "lastName": "Dan",
      "email": "Smith",
      "isNew": true,
      "image": "base64encodedimage",
      "imageType": "image/jpeg"
    }
    ```

**2.3 Pets**
Manages pet-related operations.

* GET /pets/all
  * Description: Retrieves all pets owned by the authenticated user.
  * Response:
    * 200 OK: List of pets.
    * 204 No Content: No pets found.
    * 403 Forbidden: Unauthorized access.
    * 500 Internal Server Error: Server error.
    ```json
      [
          {
          "id": 1,
          "name": "Buddy",
          "breed": "Golden Retriever",
          "dateOfBirth": "2019-01-01",
          "type": "Dog",
          "weight": "30.0",
          "isMale": true,
          "image": "base64encodedimage",
          "imageType": "image/jpeg"
          }
      ]
    ```

* GET /pets/{id}
  * Description: Retrieves the pet with the specified ID.
  * Response:
    * 200 OK: Pet details.
    * 403 Forbidden: Unauthorized access.
    * 404 Not Found: "Pet not found."
    * 500 Internal Server Error: Server error.
    ```json
    {
      "id": 1,
      "name": "Buddy",
      "breed": "Golden Retriever",
      "dateOfBirth": "2019-01-01",
      "type": "Dog",
      "weight": "30.0",
      "isMale": true,
      "image": "base64encodedimage",
      "imageType": "image/jpeg"
    }
    ```

* POST /pets/add
  * Description: Creates a new pet entry for the authenticated user.
  * Request Body:
    ```json
    {
      "id": null,
      "name": "Buddy",
      "breed": "Golden Retriever",
      "dateOfBirth": "2019-01-01",
      "type": "Dog",
      "weight": "30.0",
      "isMale": true,
      "image": "base64encodedimage",
      "imageType": "image/jpeg"
    }
    ```
  * Response:
    * 201 OK: "Pet created successfully."
    * 400 Bad Request: "Invalid request body."
    * 403 Forbidden: Unauthorized access.
    * 409 Conflict: "Pet creation failed."
    * 500 Internal Server Error: Server error.
    ```json
    {
      "id": 1,
      "name": "Buddy",
      "breed": "Golden Retriever",
      "dateOfBirth": "2019-01-01",
      "type": "Dog",
      "weight": "30.0",
      "isMale": true,
      "image": "base64encodedimage",
      "imageType": "image/jpeg"
    }
    ```

* PUT /pets/update/{id}
  * Description: Updates the pet with the specified ID.
  * Request Body:
    ```json
    {
      "id": 1,
      "name": "Buddy",
      "breed": "Golden Retriever",
      "dateOfBirth": "2019-01-01",
      "type": "Dog",
      "weight": "30.0",
      "isMale": true,
      "image": "base64encodedimage",
      "imageType": "image/jpeg"
    }
    ```
    * Response:
      * 200 OK: "Pet updated successfully."
      * 400 Bad Request: "Invalid request body."
      * 403 Forbidden: Unauthorized access.
      * 404 Not Found: "Pet not found."
      * 500 Internal Server Error: Server error.
      ```json
      {
        "id": 1,
      }
      ```

* DELETE /pets/{id}
  * Description: Deletes the pet with the specified ID.
  * Response:
    * 204 No Content: Pet deleted successfully.
    * 403 Forbidden: Unauthorized access.
    * 404 Not Found: Pet not found.
    * 409 Conflict: "Pet deletion failed."
    * 500 Internal Server Error: Server error.

* POST /addpetdata
  * Description: Adds pet data to the database.
  * Response:
    * 201 OK: "Pet data added successfully."
    * 403 Forbidden: Unauthorized access.
    * 500 Internal Server Error: Server error.
      
**2.4 Veterinary Appointments**
Handles veterinary appointment-related operations.

* GET /api/veterinary-appointments/all
  * Description: Retrieves all veterinary appointments.
  * Response:
    * 200 OK: List of appointments.
    * 204 No Content: No appointments found.
    * 403 Forbidden: Unauthorized access.
    * 500 Internal Server Error: Server error.
    ```json
    [
      {
        "id": 1,
        "petId": 1,
        "userId": 1,
        "status": "SCHEDULED",
        "localDateTime": "2022-12-01T10:00:00",
        "duration": 120,
        "cost": 150.0
      }
    ]
    ```

* GET /api/veterinary-appointments/{id}
  * Description: Retrieves the veterinary appointment with the specified ID.
  * Response:
    * 200 OK: Appointment details.
    * 403 Forbidden: Unauthorized access.
    * 404 Not Found: "Appointment not found."
    * 500 Internal Server Error: Server error.
    ```json
    {
      "id": 1,
      "petId": 1,
      "userId": 1,
      "status": "SCHEDULED",
      "localDateTime": "2022-12-01T10:00:00",
      "duration": 120,
      "cost": 150.0
    }
    ```

* POST /api/veterinary-appointments/add
  * Description: Creates a new veterinary appointment.
  * Request Body:
    ```json
    {
        "id": null,
        "petId": 1,
        "userId": 1,
        "status": "SCHEDULED",
        "localDateTime": "2022-12-01T10:00:00",
        "duration": 120,
        "cost": 150.0
    }
    ```
    * Response:
      * 201 OK: "Appointment created successfully."
      * 400 Bad Request: "Invalid request body."
      * 403 Forbidden: Unauthorized access.
      * 404 Not Found: "Pet or user not found."
      * 409 Conflict: "Appointment creation failed."
      * 500 Internal Server Error: Server error.
      ```json
      {
        "id": 1,
        "petId": 1,
        "userId": 1,
        "status": "SCHEDULED",
        "localDateTime": "2022-12-01T10:00:00",
        "duration": 120,
        "cost": 150.0
      }
      ```

* PUT /api/veterinary-appointments/update/{id}
  * Description: Updates the veterinary appointment with the specified ID.
  * Request Body:
    ```json
    {
        "id": 1,
        "petId": 1,
        "userId": 1,
        "status": "SCHEDULED",
        "localDateTime": "2022-12-01T10:00:00",
        "duration": 120,
        "cost": 150.0
      }
    ```
    * Response:
      * 200 OK: "Appointment updated successfully."
      * 400 Bad Request: "Invalid request body."
      * 403 Forbidden: Unauthorized access.
      * 404 Not Found: "Appointment not found."
      * 409 Conflict: "Appointment update failed."
      * 500 Internal Server Error: Server error.
      ```json
      {
        "id": 1,
        "petId": 1,
        "userId": 1,
        "status": "SCHEDULED",
        "localDateTime": "2022-12-01T10:00:00",
        "duration": 120,
        "cost": 150.0
      }
      ```

* DELETE /api/veterinary-appointments/{id}
  * Description: Deletes the veterinary appointment with the specified ID.
  * Response:
    * 204 No Content: Appointment deleted successfully.
    * 403 Forbidden: Unauthorized access.
    * 404 Not Found: Appointment not found.
    * 500 Internal Server Error: Server error.

# 9. FAQ and Troubleshooting
**2.1 Application Fails to Start**
* Error: Database connection refused.
  * Solution: Ensure the PostgreSQL database is running and accessible. Verify the connection string, username, and password in the environment variables.
  * Command to check:
  ```bash
  docker ps 
  ```
* Error Port 8080 is already in use.
  * Solution: Stop the conflicting service or change the application's port in the application.properties file:
  ```
  server.port=8081
  ```

**2.2 Cannot Upload or Retrieve Images**
* Cause: Image data is not being stored in the database or incorrectly encoded.
  * Solution:
    * Verify the imageData column is of type OID.
    * Ensure the image is correctly Base64-encoded before saving.
    * Check for any constraints or size limits in the database.

**2.3 Email Notifications Are Not Sent**
* Cause: Incorrect SMTP configuration.
  * Solution:
    * Verify the spring.mail configuration in the application.properties file.
    * Check the SMTP server logs for errors.
    * For Gmail, ensure "Less secure app access" is enabled for the sender account.

**2.4 JWT Token Validation Fails**
* Error: JWT token is invalid or expired.
  * Solution:
    1. Verify that the SECURITY_JWT_SECRET_KEY in the backend matches the one used to generate the token.
    2. Ensure the token is not expired.
    3. Check the jwtExpiration configuration in the .env file.

****2.5 Deployment Issues****
* Error: Cannot bind to port 5432 for PostgreSQL.
  * Solution:
    * Ensure no other services are using port 5432 on the host machine.
    * Change the exposed port in docker-compose.yml
    ```yaml
      ports:
        - "5433:5432"
    ```
* Error: Cannot pull Docker image from Docker Hub.
  * Solution:
    * Ensure correct Docker credentials are used.
    * Run:
    ```bash
    docker login
    ```

**2.6 Performance Issues**
* Symptom: API responses are slow.
  * Solution:
    * Enable query logging to identify slow queries
    ```properties
    spring.jpa.properties.hibernate.show_sql=true
    spring.jpa.properties.hibernate.format_sql=true
    ```    
    * Add indexes to frequently queried columns (e.g., email, id).
    * Optimize JPA queries using projections.

**2.7 Image Upload Fails**
* Error: File size exceeds the allowed limit.
  * Solution: Configure file size limits in Spring Boot
  ```properties
  spring.servlet.multipart.max-file-size=5MB
  spring.servlet.multipart.max-request-size=5MB
  ```
* Error: Unsupported file type.
  * Solution: Add validation for allowed file types (e.g., image/png, image/jpeg).

### Additional Resources
* PostgreSQL Documentation: https://www.postgresql.org/docs/
* Spring Boot Reference Guide: https://docs.spring.io/spring-boot/docs/current/reference/html/
* Docker Documentation: https://docs.docker.com/

# 10. Appendices
This section provides additional information, resources, and references to support developers and administrators working with the backend server. It includes conventions, file structure, key configurations, and links to external documentation.

**Codebase Structure**
The backend server follows a modular structure for better organization and maintainability.

### Directory Layout
```plaintext
src/
├── main/
│   ├── java/org/pawpal/
│   │   ├── controller/        # Controllers handling API endpoints
│   │   ├── dto/               # Data Transfer Objects
│   │   ├── exception/         # Custom exception classes
│   │   ├── jwt/               # JWT utilities and filters
│   │   ├── mail/              # Email service utilities
│   │   ├── model/             # Entity classes
│   │   ├── repository/        # JPA repositories
│   │   ├── service/           # Business logic and service classes
│   │   ├── util/              # Utility classes
│   │   └── config/            # Security and application configuration
│   └── resources/
│       ├── application.properties # Main configuration file
│       ├── application.yml        # YAML configuration (optional)
│       ├── static/                # Static files (if applicable)
│       ├── templates/             # Thymeleaf templates for emails
│       └── sql/                   # SQL initialization scripts
├── test/                          # Unit and integration tests
└── Dockerfile                     # Docker build configuration
└── docker-compose.yml             # Docker Compose setup
```

### Naming Conventions
Adopting consistent naming conventions helps improve readability and maintainability.

**2.1 Package Naming**
* Use lowercase letters.
* Structure packages by functionality:
  * controller: For controllers.
  * service: For service classes.
  * repository: For database repositories.

**2.2 Class Naming**
* Use PascalCase for class names (e.g., AuthenticationController, UserService).
* Name entity classes based on the resource they represent (e.g., User, Pet, VeterinaryAppointment).

**2.3 Method Naming**
* Use camelCase for method names.
* Use descriptive names for methods, e.g.:
  * findUserByEmail(String email)
  * createPet(User user, PetDTO petDTO)
**2.4 File Naming**
* Follow the same naming convention as classes.
* Configuration files should reflect their purpose (e.g., application.properties, docker-compose.yml).

### Key Configurations
**3.1 application.properties**
The main configuration file for Spring Boot. Below are key settings:
```properties
spring.application.name=pawpal
spring.datasource.url=jdbc:postgresql://localhost:5435/pawpal_db
spring.datasource.username=pawpal_user
spring.datasource.password=secretpassword
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.generate-ddl=true
security.jwt.secret-key=your-secret-key
security.jwt.expiration-time=604800000

spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.protocol=smtp
spring.mail.username=your-email@gmail.com
spring.mail.password=your-email-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
spring.mail.properties.mail.mime.charset=UTF
spring.mail.default-encoding=UTF-8
```

**3.2 Docker Configuration**
Ensure your compose.yml includes environment variables for sensitive information:
```yaml
services:
  postgres:
    image: 'postgres:latest'
    environment:
      POSTGRES_USER: 'pawpal_user'
      POSTGRES_PASSWORD: 'secretpassword'
      POSTGRES_DB: 'pawpal_db'
    ports:
      - '5435:5432'
```

### References
* Spring Boot Documentation: https://spring.io/projects/spring-boot
* PostgreSQL Documentation: https://www.postgresql.org/docs/
* JWT Specification: https://jwt.io/
* Docker Documentation: https://docs.docker.com/

### Useful Tools
* IDE: IntelliJ IDEA or Eclipse for Java development.
* Database Management: pgAdmin or DBeaver for PostgreSQL.

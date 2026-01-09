# Lab 09: Developing Secure Web Applications and REST APIs - Solutions

---

# 1. Extending Admin Area (Task 1)

## Challenge Overview

**Goal**: Extend the admin area to support product management for PRODUCTMANAGER role and secure password changes for all authenticated users.

**Credentials**:
| Username | Password | Role |
| -------- | --------- | -------------- |
| alice | rabbit | SALES |
| bob | patrick | BURGERMAN |
| daisy | yellow | PRODUCTMANAGER |
| luke | force | PRODUCTMANAGER |

---

## 1.1 Listing and Deleting Products

### Vulnerability Being Addressed

| Security Concern          | Description                                                   |
| ------------------------- | ------------------------------------------------------------- |
| **Broken Access Control** | Missing role-based access control for new PRODUCTMANAGER role |

### Implementation

#### Step 1: Extend SecurityConfig for New Roles

**File**: `Marketplace-web/.../config/SecurityConfig.java`

**Initial Code (Skeleton)**:

```java
.requestMatchers("/admin/deletepurchase/*").hasRole("SALES")
.requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES")
```

**Solution Code**:

```java
.requestMatchers("/admin/deletepurchase/*").hasRole("SALES")
.requestMatchers("/admin/deleteproduct/*").hasRole("PRODUCTMANAGER")
.requestMatchers("/admin/addproduct").hasRole("PRODUCTMANAGER")
.requestMatchers("/admin/saveproduct").hasRole("PRODUCTMANAGER")
.requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES", "PRODUCTMANAGER", "BURGERMAN")
```

**Why This Matters**: Access control rules are evaluated top-to-bottom. Specific rules for product operations must come before the general `/admin/**` rule to ensure proper role enforcement.

---

#### Step 2: Extend AdminController.adminPage

**File**: `Marketplace-web/.../controller/AdminController.java`

**Solution Code**:

```java
@GetMapping("/admin/admin")
public String adminPage(Model model) {
    String role = utilityService.getRoleOfAuthenticatedUser();
    if (role.equals("MARKETING") || role.equals("SALES")) {
        Iterable<Purchase> purchases = purchaseService.findAll();
        model.addAttribute("purchases", purchases);
    } else if (role.equals("PRODUCTMANAGER")) {
        Iterable<Product> products = productService.findAll();
        model.addAttribute("products", products);
        model.addAttribute("username", utilityService.getUsernameOfAuthenticatedUser());
    }
    return "admin/admin";
}
```

**Key Points**:

- `products` model attribute contains all products for display
- `username` model attribute enables ownership checks in the template
- BURGERMAN role gets an empty admin page (no special content)

---

#### Step 3: Implement deleteProduct with Authorization Check

**Solution Code**:

```java
@PostMapping("/admin/deleteproduct/{id}")
public String deleteProduct(@PathVariable(name = "id") int id) {
    Product product = productService.findById(id);
    if (product != null) {
        String currentUsername = utilityService.getUsernameOfAuthenticatedUser();
        if (!product.getUsername().equals(currentUsername)) {
            throw new AccessDeniedException("");
        }
        productService.delete(product);
    }
    return "redirect:/admin/admin";
}
```

**Security Pattern**: Server-side authorization check is mandatory. Never rely solely on UI restrictions (hiding buttons) as they can be bypassed by sending direct POST requests.

---

## 1.2 Adding New Products

### Bean Validation Annotations

**File**: `Marketplace-common/.../model/Product.java`

**Initial Code (No validation)**:

```java
private String description;
private BigDecimal price;
```

**Solution Code**:

```java
@NotNull(message = "Description is missing.")
@Pattern(regexp = "^[a-zA-Z0-9 ,'\\-]{10,100}$",
        message = "Please insert a valid description (10-100 characters: letters / digits / - / , / ').")
private String description;

@NotNull(message = "Price is missing.")
@PositiveOrZero(message = "Please insert a valid price (between 0 and 999999.99, with at most two decimal places).")
@Digits(integer = 6, fraction = 2, message = "Please insert a valid price (between 0 and 999999.99, with at most two decimal places).")
private BigDecimal price;
```

### Validation Breakdown

| Field       | Annotation        | Purpose                                     |
| ----------- | ----------------- | ------------------------------------------- |
| description | `@NotNull`        | Prevent null values                         |
| description | `@Pattern`        | Whitelist allowed characters (10-100 chars) |
| price       | `@NotNull`        | Prevent null values                         |
| price       | `@PositiveOrZero` | Ensure non-negative price                   |
| price       | `@Digits(6,2)`    | Max 6 integer digits, max 2 decimal places  |

---

### saveProduct Controller Method

**Solution Code**:

```java
@PostMapping("/admin/saveproduct")
public String saveProduct(@ModelAttribute @Valid Product product, BindingResult bindingResult,
                          Model model, RedirectAttributes redirectAttributes) {
    if (bindingResult.hasErrors()) {
        model.addAttribute("product", product);
        return "admin/addproduct";
    } else {
        product.setUsername(utilityService.getUsernameOfAuthenticatedUser());
        productService.save(product);
        redirectAttributes.addFlashAttribute("message", "The product could successfully be added.");
        return "redirect:/admin/admin";
    }
}
```

**Key Points**:

- `@Valid` triggers Bean Validation
- `BindingResult` captures validation errors
- Username is set server-side (never trust client input)
- Flash attributes survive redirects

---

## 1.3 Secure Password Change

### Vulnerability in Original Design

The original `ChangePassword` class only had `newPassword` field - no verification of the old password. This is insecure because:

1. **Session hijacking**: Attacker with session access could change password without knowing current one
2. **CSRF attacks**: Malicious site could change victim's password

### Solution

**File**: `Marketplace-common/.../model/ChangePassword.java`

**Initial Code (Insecure)**:

```java
public class ChangePassword {
    @NotNull(message = "New password is missing.")
    @Size(min = 4, max = 20, message = "Please insert a valid new password...")
    private String newPassword;
}
```

**Solution Code (Secure)**:

```java
public class ChangePassword {
    @NotNull(message = "Old password is missing.")
    @Size(min = 4, max = 20, message = "Please insert a valid old password...")
    private String oldPassword;

    @NotNull(message = "New password is missing.")
    @Size(min = 4, max = 20, message = "Please insert a valid new password...")
    private String newPassword;
}
```

---

### UserService.changePassword Implementation

**File**: `Marketplace-common/.../service/UserService.java`

**Initial Code (Skeleton)**:

```java
public boolean changePassword(String username, ChangePassword changePassword) {
    User user = findByUsername(username);
    if (user == null) return false;
    // Implement
    repo.save(user);
    return true;
}
```

**Solution Code**:

```java
public boolean changePassword(String username, ChangePassword changePassword) {
    User user = findByUsername(username);
    if (user == null) return false;

    // Verify the old password matches the stored hash
    if (!passwordEncoder.matches(changePassword.getOldPassword(), user.getPasswordHash())) {
        return false;
    }

    // Hash the new password and update the user
    String newPasswordHash = passwordEncoder.encode(changePassword.getNewPassword());
    user.setPasswordHash(newPasswordHash);

    try {
        repo.save(user);
        return true;
    } catch (DataAccessException e) {
        return false;
    }
}
```

**Security Pattern**: Always use `BCryptPasswordEncoder.matches()` to verify passwords, never compare hashes directly.

---

### Access Control for Account Settings

**Question**: Do we need to add access control rules for `/admin/accountsettings`?

**Answer**: No additional rules are needed. The existing rule:

```java
.requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES", "PRODUCTMANAGER", "BURGERMAN")
```

Already covers `/admin/accountsettings` and `/admin/changepassword`, making them accessible to all authenticated users with any admin role.

---

# 2. Login Input Validation and Throttling (Task 2)

## Challenge Overview

**Goal**: Prevent online password guessing attacks by validating login input and implementing username-based throttling.

---

## 2.1 Login Input Validation

### Why Input Validation During Login?

Even during login, user input should be validated:

1. Prevents processing of malformed data
2. Protects against injection attacks
3. Early rejection saves processing resources

### The Bypass Problem

After adding input validation via `/public/login-check`, an attacker could bypass it by sending POST requests directly to `/public/login`.

**Solution**: Block direct POST requests to `/public/login`

**File**: `Marketplace-web/.../config/SecurityConfig.java`

```java
.addFilterBefore(blockLoginPostRequestFilter, UsernamePasswordAuthenticationFilter.class)
```

The `BlockLoginPostRequestFilter` returns HTTP 403 for any direct POST to `/public/login`, forcing all login attempts through the validation endpoint.

---

## 2.2 Login Throttling Implementation

### Throttling Specification

| Rule                         | Value                                         |
| ---------------------------- | --------------------------------------------- |
| Failed attempts before block | 3                                             |
| Block duration               | 60 seconds                                    |
| Post-unblock attempts        | 1 (then blocked again on failure)             |
| Non-existing usernames       | Not tracked (prevents DoS via fake usernames) |

### LoginThrottlingService

**File**: `Marketplace-common/.../service/LoginThrottlingService.java`

**Initial Code (Skeleton)**:

```java
public void loginFailed(String username) { /* Implement */ }
public void loginSuccessful(String username) { /* Implement */ }
public boolean isBlocked(String username) { return false; }
```

**Solution Code**:

```java
@Service
public class LoginThrottlingService {
    private static final int BLOCKING_TIME = 60;
    private static final int BLOCKING_LIMIT = 3;

    // Track failed login attempts: username -> number of failed attempts
    private final ConcurrentHashMap<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    // Track when user was blocked: username -> timestamp when blocked (in seconds)
    private final ConcurrentHashMap<String, Long> blockedUsers = new ConcurrentHashMap<>();

    public void loginFailed(String username) {
        int attempts = failedAttempts.getOrDefault(username, 0) + 1;
        failedAttempts.put(username, attempts);
        if (attempts >= BLOCKING_LIMIT) {
            blockedUsers.put(username, System.currentTimeMillis() / 1000);
        }
    }

    public void loginSuccessful(String username) {
        failedAttempts.remove(username);
        blockedUsers.remove(username);
    }

    public boolean isBlocked(String username) {
        Long blockedTime = blockedUsers.get(username);
        if (blockedTime == null) return false;

        long currentTime = System.currentTimeMillis() / 1000;
        if (currentTime - blockedTime < BLOCKING_TIME) {
            return true;  // Still blocked
        } else {
            // Blocking time expired, allow one attempt
            blockedUsers.remove(username);
            failedAttempts.put(username, BLOCKING_LIMIT - 1);  // Next failure = blocked again
            return false;
        }
    }
}
```

**Design Decisions**:

- Uses `ConcurrentHashMap` for thread safety
- In-memory storage (no database) for performance
- Returns immediately (no `sleep()`) to prevent thread exhaustion DoS

---

### CustomAuthFailureHandler

**File**: `Marketplace-web/.../config/CustomAuthFailureHandler.java`

```java
@Override
public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                    AuthenticationException exception) throws IOException {
    String username = request.getParameter("username");

    // Only track failed logins for existing users to prevent DoS
    if (username != null && userService.findByUsername(username) != null) {
        loginThrottlingService.loginFailed(username);
    }

    response.sendRedirect("/public/login?error=true");
}
```

---

### CustomAuthSuccessHandler

**File**: `Marketplace-web/.../config/CustomAuthSuccessHandler.java`

```java
@Override
public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                    Authentication authentication) throws IOException {
    String username = authentication.getName();
    loginThrottlingService.loginSuccessful(username);
    response.sendRedirect("/admin/admin");
}
```

---

### LoginThrottlingFilter

**File**: `Marketplace-web/.../config/LoginThrottlingFilter.java`

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                FilterChain filterChain) throws ServletException, IOException {
    if ("/public/login-check".equals(request.getServletPath()) && "POST".equals(request.getMethod())) {
        String username = request.getParameter("username");
        if (username != null && loginThrottlingService.isBlocked(username)) {
            response.sendRedirect("/public/login?blocked=true");
            return;
        }
    }
    filterChain.doFilter(request, response);
}
```

---

### SecurityConfig Filter Chain

```java
.formLogin(formLoginConfigurer -> formLoginConfigurer
    .loginPage("/public/login")
    .failureHandler(authFailureHandler)    // Custom handler instead of failureUrl
    .successHandler(authSuccessHandler)    // Custom handler
    .permitAll())
.addFilterBefore(blockLoginPostRequestFilter, UsernamePasswordAuthenticationFilter.class)
.addFilterBefore(loginThrottlingFilter, UsernamePasswordAuthenticationFilter.class);
```

**Filter Order**:

1. `BlockLoginPostRequestFilter` - Blocks direct POST to `/public/login`
2. `LoginThrottlingFilter` - Checks if username is blocked
3. `UsernamePasswordAuthenticationFilter` - Spring's built-in auth filter

---

### Attack Limitation Calculation

With this mechanism:

- 1 attempt every 60 seconds per username
- = 60 attempts per hour
- = **1,440 attempts per day maximum**

Even with many computers/IPs, an attacker is limited to 1,440 password attempts per username per day.

---

# 3. Encrypting Credit Card Numbers (Task 3)

## Challenge Overview

**Goal**: Encrypt credit card numbers in the database using AES/GCM to protect against database breaches, SQL injection, or malicious DBAs.

---

## Encryption Specification

| Parameter     | Value               |
| ------------- | ------------------- |
| Algorithm     | AES/GCM/NoPadding   |
| Key Size      | 128 bits            |
| IV Size       | 16 bytes (128 bits) |
| Auth Tag Size | 128 bits            |
| Storage       | Base64(IV + CT)     |

---

## AESCipherService Implementation

**File**: `Marketplace-common/.../service/AESCipherService.java`

**Initial Code (Skeleton)**:

```java
public byte[] encrypt(byte[] plaintext) { return null; }
public byte[] decrypt(byte[] iv_ciphertext) { return null; }
```

**Solution Code**:

```java
public byte[] encrypt(byte[] plaintext) {
    try {
        // Generate a random IV
        byte[] iv = new byte[BLOCKSIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_FULL);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        // Encrypt the plaintext
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Concatenate IV and ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return result;
    } catch (Exception e) {
        throw new RuntimeException("Encryption failed", e);
    }
}

public byte[] decrypt(byte[] iv_ciphertext) {
    try {
        // Extract IV from the beginning
        byte[] iv = new byte[BLOCKSIZE];
        System.arraycopy(iv_ciphertext, 0, iv, 0, BLOCKSIZE);

        // Extract ciphertext (rest of the data)
        byte[] ciphertext = new byte[iv_ciphertext.length - BLOCKSIZE];
        System.arraycopy(iv_ciphertext, BLOCKSIZE, ciphertext, 0, ciphertext.length);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_FULL);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTH_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        return cipher.doFinal(ciphertext);
    } catch (Exception e) {
        throw new RuntimeException("Decryption failed", e);
    }
}
```

---

## Why GCM Mode?

| Feature         | GCM Provides                                           |
| --------------- | ------------------------------------------------------ |
| Confidentiality | AES encryption protects data secrecy                   |
| Integrity       | Auth tag detects tampering                             |
| Authenticity    | Verifies data wasn't modified                          |
| No Padding      | GCM is a stream cipher mode, no padding oracle attacks |

---

## JPA AttributeConverter

**File**: `Marketplace-common/.../model/Purchase.java`

Add the `@Convert` annotation to the credit card field:

```java
@NotNull(message = "Credit card number is missing.")
@CreditCardCheck
@Convert(converter = AESConverter.class)
private String creditCardNumber;
```

This automatically:

1. **On save**: Encrypts plaintext → Base64(IV + ciphertext) → stores in DB
2. **On read**: Reads from DB → Base64 decode → decrypts → returns plaintext

---

## Database Verification

After implementation, credit cards in the database look like:

```
fGd10a46VT4C99RTtDJZqG0XRa8/oPElDBUcMh3+Qs4qFHS59+DU1CgLS1dqGZZ61+Yp
p84vqX+tI4C9wlvW3a2VqCw0O3EB/+6FjnriOsqiRPbxw7fJ3orQ04au3IFsQXqJFBcB
```

Each entry is different due to random IVs, but all decrypt to the same plaintext.

---

# 4. REST API for Product Managers (Task 4)

## Challenge Overview

**Goal**: Extend the REST API with endpoints for product managers to list, create, and delete products, with JWT authentication.

---

## 4.1 REST API Endpoints

| Method | Endpoint                  | Description        | Role Required  |
| ------ | ------------------------- | ------------------ | -------------- |
| GET    | /rest/admin/products      | List all products  | PRODUCTMANAGER |
| POST   | /rest/admin/products      | Create new product | PRODUCTMANAGER |
| DELETE | /rest/admin/products/{id} | Delete own product | PRODUCTMANAGER |

---

## SecurityConfig (REST)

**File**: `Marketplace-rest/.../config/SecurityConfig.java`

```java
.authorizeHttpRequests(auth -> auth
    .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
    .requestMatchers("/rest/public/*", "/rest/auth/*").permitAll()
    .requestMatchers("/rest/admin/purchases").hasAnyRole("MARKETING", "SALES")
    .requestMatchers("/rest/admin/purchases/*").hasRole("SALES")
    .requestMatchers("/rest/admin/products").hasRole("PRODUCTMANAGER")
    .requestMatchers("/rest/admin/products/*").hasRole("PRODUCTMANAGER")
    .anyRequest().denyAll()
)
```

---

## AdminController (REST)

**File**: `Marketplace-rest/.../controller/AdminController.java`

### GET /rest/admin/products

```java
@GetMapping(value = "/admin/products", produces = MediaType.APPLICATION_JSON_VALUE)
public List<AdminProduct> getProducts() {
    List<AdminProduct> adminProducts = new ArrayList<>();
    for (Product product : productService.findAll()) {
        adminProducts.add(new AdminProduct(product));
    }
    return adminProducts;
}
```

Returns:

```json
[
  {
    "productID": 1,
    "description": "DVD Life of Brian...",
    "price": 5.95,
    "username": "daisy"
  },
  {
    "productID": 2,
    "description": "Ferrari F50...",
    "price": 250000.0,
    "username": "luke"
  }
]
```

---

### POST /rest/admin/products

```java
@PostMapping(value = "/admin/products", consumes = MediaType.APPLICATION_JSON_VALUE)
@ResponseStatus(HttpStatus.NO_CONTENT)
public void postProduct(@RequestBody @Valid Product product) {
    product.setUsername(utilityService.getUsernameOfAuthenticatedUser());
    if (!productService.save(product)) {
        throw new RuntimeException("Failed to save product");
    }
}
```

**Key Points**:

- `@Valid` triggers Bean Validation (same annotations as web app)
- Username set server-side from JWT token
- Returns 204 No Content on success

---

### DELETE /rest/admin/products/{id}

```java
@DeleteMapping("/admin/products/{id}")
@ResponseStatus(HttpStatus.NO_CONTENT)
public void deleteProduct(@PathVariable(name = "id")
                          @Min(value = 1, message = "The product ID must be between 1 and 999'999.")
                          @Max(value = 999999, message = "The product ID must be between 1 and 999'999.") int id) {
    Product product = productService.findById(id);
    if (product == null) {
        throw new InvalidParameterException("The product with product ID = '" + id + "' does not exist.");
    }
    String currentUsername = utilityService.getUsernameOfAuthenticatedUser();
    if (!product.getUsername().equals(currentUsername)) {
        throw new AccessDeniedException("");
    }
    productService.delete(product);
}
```

**Error Responses**:
| Condition | Response |
| ---------------------------- | --------------------------------------------------------------- |
| Invalid ID range | 400 `{"error": "The product ID must be between 1 and 999'999."}`|
| Product not found | 400 `{"error": "The product with product ID = '999' does not exist."}`|
| Deleting another's product | 403 `{"error": "Access denied, only the own products can be deleted."}`|

---

## GlobalExceptionHandler (REST)

**File**: `Marketplace-rest/.../config/GlobalExceptionHandler.java`

Added handler for `AccessDeniedException`:

```java
@ExceptionHandler(AccessDeniedException.class)
public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException e) {
    return createResponse(HttpStatus.FORBIDDEN, "Access denied, only the own products can be deleted.");
}
```

---

## 4.2 REST API Login Throttling

### AuthController

**File**: `Marketplace-rest/.../controller/AuthController.java`

```java
@PostMapping(value = "/auth/authenticate", ...)
public JWTRole postAuthenticate(@RequestBody @Valid Credentials credentials) {
    String username = credentials.getUsername();

    // Check if user is blocked
    if (loginThrottlingService.isBlocked(username)) {
        throw new InvalidParameterException(
            "You are temporarily blocked due to multiple failed login attempts. Please try again in one minute.");
    }

    UsernamePasswordAuthenticationToken authToken =
            new UsernamePasswordAuthenticationToken(username, credentials.getPassword());
    Authentication authentication;
    try {
        authentication = authenticationManager.authenticate(authToken);
    } catch (BadCredentialsException e) {
        // Only track failed logins for existing users
        if (userService.findByUsername(username) != null) {
            loginThrottlingService.loginFailed(username);
        }
        throw new InvalidParameterException("Invalid username or password, please try again.");
    }

    // Login successful - clear failed attempts
    loginThrottlingService.loginSuccessful(username);

    String jwt = jwtService.createJWT(username);
    String role = authentication.getAuthorities().iterator().next().getAuthority();
    return new JWTRole(jwt, role.startsWith("ROLE_") ? role.substring(5) : role);
}
```

**Same throttling rules apply**:

- 3 failed attempts → blocked for 60 seconds
- Non-existing usernames not tracked
- Successful login clears all tracking

---

# Setup Instructions

## Prerequisites

- Docker & Docker Compose
- Java 17+
- Maven (or use the Maven wrapper in the project)
- IntelliJ IDEA (recommended) or another IDE

---

## Step 1: Start the Database

```bash
cd /path/to/labs/09

# Start MySQL container
docker compose up -d

# Verify it's running
docker compose ps

# Wait ~10 seconds, then check logs
docker compose logs mysql
```

**To reset the database:**

```bash
docker compose down -v && docker compose up -d
```

---

## Step 2: Run the Web Application

### Using IntelliJ

1. Open `Marketplace_Lab` folder
2. Select **"Marketplace Web"** from run configuration
3. Click Run
4. Wait for "Started MarketplaceApplication"

### Using Command Line

```bash
cd Marketplace_Lab
./mvnw clean install -DskipTests
./mvnw spring-boot:run -pl Marketplace-web
```

Access at: `https://localhost:8443`

---

## Step 3: Run REST API (for Task 4)

**Stop Web App first!** (Both use port 8443)

```bash
./mvnw spring-boot:run -pl Marketplace-rest
```

---

## Step 4: Run REST API Tests

1. Reset database: `docker compose down -v && docker compose up -d`
2. Start REST API
3. Run tests from `Marketplace_Lab_REST-Test`:

```bash
cd Marketplace_Lab_REST-Test
./mvnw exec:java -Dexec.mainClass="Test"
```

---

## After Task 3: Encrypt Existing Credit Cards

```bash
docker exec -i marketplace-mysql mysql -uroot -proot < Marketplace_UpdateEncryptedCreditCards.sql
```


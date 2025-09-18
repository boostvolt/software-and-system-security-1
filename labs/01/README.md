# Lab 01

## Simple Encoder

### Vulnerabilities

1. **Information Disclosure**: Cookie contains base64-encoded file path
2. **Path Traversal**: No input validation allows `../` directory traversal

### Attack Steps

1. **Cookie Analysis**: `ZGRwajA0YzM1NWx4bnpydC50eHQ=` → `ddpj04c355lxnzrt.txt`
2. **Source Code Disclosure**: `../../../opt/www/index.php` (base64: `Li4vLi4vLi4vb3B0L3d3dy9pbmRleC5waHA=`) revealed flag location: `/secret/flag.txt`
3. **Flag Retrieval**: `../../secret/flag.txt` (base64: `Li4vLi4vc2VjcmV0L2ZsYWcudHh0`) traverses from `/tmp/php/` to `/secret/flag.txt`

### Flag

**Flag**: fceca90a-3c9a-4b98-8578-16da67370c8e

## SCHOGGI: API Mass Assignment

### Vulnerability
**Mass Assignment**: API endpoints accept more parameters than intended, allowing unauthorized modification of object properties

### Attack Steps

1. **API Reconnaissance**: `/api/users` GET endpoint revealed user structure with `"role": "user"` attribute
2. **Request Interception**: Used Burp Suite to intercept POST request to `/api/account` (profile update)
3. **Parameter Injection**: Added `"role": "admin"` to profile update request via Burp Repeater
4. **Privilege Escalation**: Application processed unauthorized parameter, escalating alice to admin

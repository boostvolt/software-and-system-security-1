# Task 1

Question: Finally, think about whether you must adapt method securityFilterChain in class SecurityConfig to make sure that access control for the account settings is configured correctly. If yes, add the re quired configuration(s). Explain whether you have to add anything or not.

Answer: NO additional configuration is needed.
Looking at the current SecurityConfig.java:42:

.requestMatchers("/admin/**").hasAnyRole("MARKETING", "SALES", "PRODUCTMANAGER", "BURGERMAN")

This rule already covers:
- /admin/accountsettings (GET)
- /admin/changepassword (POST)

Both endpoints are accessible to all authenticated users with any role, which is exactly what's required. Every user should be able to change their own password.

# Task 2
Question: Verify that input validation indeed works correctly. However, the current implementation is not secure yet, and it's actually possible for an attacker to circumvent input validation during login. Do you have an idea why this is so? Write your reasoning into the following box.

Answer: The form submits to `/public/login-check` where validation happens, then forwards to `/public/login` for Spring Security authentication. However, an attacker can bypass validation entirely by sending a POST request directly to `/public/login` instead of `/public/login-check`. This skips the `processLogin()` validation method completely, and Spring Security's `UsernamePasswordAuthenticationFilter` still processes the request.

An attacker can exploit this by using Burp Suite or curl to intercept/craft a request, change the URL from `/public/login-check` to `/public/login`, and send malformed credentials (e.g., 1 character username) directly.

The fix is the `BlockLoginPostRequestFilter` which blocks direct POST requests to `/public/login` and returns HTTP 403 Forbidden.
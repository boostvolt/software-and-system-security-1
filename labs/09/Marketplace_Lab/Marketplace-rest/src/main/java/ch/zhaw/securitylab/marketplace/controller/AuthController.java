package ch.zhaw.securitylab.marketplace.controller;

import ch.zhaw.securitylab.marketplace.model.*;
import ch.zhaw.securitylab.marketplace.service.JWTService;
import ch.zhaw.securitylab.marketplace.service.LoginThrottlingService;
import ch.zhaw.securitylab.marketplace.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.security.InvalidParameterException;

@RestController
@RequestMapping("/rest")
public class AuthController {

    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final LoginThrottlingService loginThrottlingService;
    private final UserService userService;

    public AuthController(JWTService jwtService, AuthenticationManager authenticationManager,
                          LoginThrottlingService loginThrottlingService,
                          UserService userService) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.loginThrottlingService = loginThrottlingService;
        this.userService = userService;
    }

    @PostMapping(value = "/auth/authenticate", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public JWTRole postAuthenticate(@RequestBody @Valid Credentials credentials) {
        String username = credentials.getUsername();

        // Check if user is blocked
        if (loginThrottlingService.isBlocked(username)) {
            throw new InvalidParameterException("You are temporarily blocked due to multiple failed login attempts. Please try again in one minute.");
        }

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, credentials.getPassword());
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(authToken);
        } catch (BadCredentialsException e) {
            // Only track failed logins for existing users
            if (userService.findByUsername(username) != null) {
                loginThrottlingService.loginFailed(username);
            }
            throw new InvalidParameterException("Invalid username or password, please try again.");
        }

        // Login successful - clear failed attempts
        loginThrottlingService.loginSuccessful(username);

        String jwt = jwtService.createJWT(username);
        String fullRole = authentication.getAuthorities().iterator().next().getAuthority();
        String role = fullRole.startsWith("ROLE_") ? fullRole.substring(5) : fullRole;
        return new JWTRole(jwt, role);
    }
}
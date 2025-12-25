package ch.zhaw.securitylab.marketplace.config;

import ch.zhaw.securitylab.marketplace.service.LoginThrottlingService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@Component
public class CustomAuthSuccessHandler implements AuthenticationSuccessHandler {

    private final LoginThrottlingService loginThrottlingService;

    public CustomAuthSuccessHandler(LoginThrottlingService loginThrottlingService) {
        this.loginThrottlingService = loginThrottlingService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // Get the username of the user that just logged in successfully
        String username = authentication.getName();

        // Clear failed login tracking for this user
        loginThrottlingService.loginSuccessful(username);

        // Redirect the user to the admin area
        response.sendRedirect("/admin/admin");
    }
}
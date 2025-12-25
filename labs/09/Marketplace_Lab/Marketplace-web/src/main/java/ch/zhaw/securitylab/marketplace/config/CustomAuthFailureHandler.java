package ch.zhaw.securitylab.marketplace.config;

import ch.zhaw.securitylab.marketplace.model.User;
import ch.zhaw.securitylab.marketplace.service.LoginThrottlingService;
import ch.zhaw.securitylab.marketplace.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthFailureHandler implements AuthenticationFailureHandler {

    private final LoginThrottlingService loginThrottlingService;
    private final UserService userService;

    public CustomAuthFailureHandler(LoginThrottlingService loginThrottlingService,
                                    UserService userService) {
        this.loginThrottlingService = loginThrottlingService;
        this.userService = userService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        // Get the username that was sent during the failed login
        String username = request.getParameter("username");

        // Only track failed logins for existing users to prevent DoS via fictitious usernames
        if (username != null && userService.findByUsername(username) != null) {
            loginThrottlingService.loginFailed(username);
        }

        // Redirect the user to the login page
        response.sendRedirect("/public/login?error=true");
    }
}
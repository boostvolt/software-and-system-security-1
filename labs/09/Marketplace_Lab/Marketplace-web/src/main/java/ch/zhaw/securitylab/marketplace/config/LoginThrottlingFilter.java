package ch.zhaw.securitylab.marketplace.config;

import ch.zhaw.securitylab.marketplace.service.LoginThrottlingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class LoginThrottlingFilter extends OncePerRequestFilter {

    private final LoginThrottlingService loginThrottlingService;

    public LoginThrottlingFilter(LoginThrottlingService loginThrottlingService) {
        this.loginThrottlingService = loginThrottlingService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // The filter should only apply to POST requests to /public/login-check
        if ("/public/login-check".equals(request.getServletPath()) && "POST".equals(request.getMethod())) {
            String username = request.getParameter("username");
            if (username != null && loginThrottlingService.isBlocked(username)) {
                response.sendRedirect("/public/login?blocked=true");
                return;
            }
        }

        // Invoke the next filter in the chain (if any)
        filterChain.doFilter(request, response);
    }
}
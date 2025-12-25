package ch.zhaw.securitylab.marketplace.service;

import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginThrottlingService {

    private static final int BLOCKING_TIME = 60;
    private static final int BLOCKING_LIMIT = 3;

    // Track failed login attempts: username -> number of failed attempts
    private final ConcurrentHashMap<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    // Track when user was blocked: username -> timestamp when blocked (in seconds)
    private final ConcurrentHashMap<String, Long> blockedUsers = new ConcurrentHashMap<>();

    /**
     * Is called to inform that the login with username has failed.
     *
     * @param username The username for which the login failed
     */
    public void loginFailed(String username) {
        // Get current number of failed attempts
        int attempts = failedAttempts.getOrDefault(username, 0) + 1;
        failedAttempts.put(username, attempts);

        // If reached blocking limit, record the block time
        if (attempts >= BLOCKING_LIMIT) {
            blockedUsers.put(username, System.currentTimeMillis() / 1000);
        }
    }

    /**
     * Is called to inform that the login with username has succeeded.
     *
     * @param username The username for which the login succeeded
     */
    public void loginSuccessful(String username) {
        // Remove all tracking data for this user
        failedAttempts.remove(username);
        blockedUsers.remove(username);
    }

    /**
     * Returns whether the user username is blocked.
     *
     * @param username The username to check
     * @return true if the user is blocked, false otherwise
     */
    public boolean isBlocked(String username) {
        Long blockedTime = blockedUsers.get(username);
        if (blockedTime == null) {
            return false;
        }

        long currentTime = System.currentTimeMillis() / 1000;
        if (currentTime - blockedTime < BLOCKING_TIME) {
            // Still blocked
            return true;
        } else {
            // Blocking time has expired, reset to allow one attempt
            // After one failed attempt, they'll be blocked again
            blockedUsers.remove(username);
            failedAttempts.put(username, BLOCKING_LIMIT - 1);
            return false;
        }
    }
}
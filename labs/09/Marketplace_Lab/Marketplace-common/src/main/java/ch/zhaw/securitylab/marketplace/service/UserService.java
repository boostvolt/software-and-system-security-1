package ch.zhaw.securitylab.marketplace.service;

import ch.zhaw.securitylab.marketplace.model.ChangePassword;
import ch.zhaw.securitylab.marketplace.model.User;
import ch.zhaw.securitylab.marketplace.repository.UserRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repo, PasswordEncoder passwordEncoder) {
        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = repo.findByUsername(username);
        if (user.isPresent()) {
            User userObj = user.get();
            return org.springframework.security.core.userdetails.User.builder()
                    .username(userObj.getUsername())
                    .password(userObj.getPasswordHash())
                    .roles(userObj.getRole())
                    .build();
        } else {
            throw new UsernameNotFoundException(username);
        }
    }

    public User findByUsername(String username) {
        Optional<User> user = repo.findByUsername(username);
        if (user.isPresent()) {
            return user.get();
        } else {
            return null;
        }
    }

    /**
     * Changes the password of a user.
     *
     * @param username The username for which to change the password
     * @param changePassword The new password
     * @return whether password change was successful (true) or not (false)
     */
    public boolean changePassword(String username, ChangePassword changePassword) {

        // Get the User entity of user username from the database
        User user = findByUsername(username);
        if (user == null) {
            return false;
        }

        // Verify the old password matches the stored hash
        if (!passwordEncoder.matches(changePassword.getOldPassword(), user.getPasswordHash())) {
            return false;
        }

        // Hash the new password and update the user
        String newPasswordHash = passwordEncoder.encode(changePassword.getNewPassword());
        user.setPasswordHash(newPasswordHash);

        // Save the modified User entity in the database
        try  {
            repo.save(user);
            return true;
        } catch (DataAccessException e) {
            return false;
        }
    }
}
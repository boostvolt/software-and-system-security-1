package ch.zhaw.securitylab.marketplace.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class Credentials {

    @NotNull(message = "Username is missing.")
    @Size(min = 3, max = 12, message = "Please insert a valid username (between 3 and 12 characters).")
    private String username;
    @NotNull(message = "Password is missing.")
    @Size(min = 4, max = 20, message = "Please insert a valid password (between 4 and 20 characters).")
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
package ch.zhaw.securitylab.marketplace.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class ChangePassword {

    @NotNull(message = "Old password is missing.")
    @Size(min = 4, max = 20, message = "Please insert a valid old password (between 4 and 20 characters).")
    private String oldPassword;

    @NotNull(message = "New password is missing.")
    @Size(min = 4, max = 20, message = "Please insert a valid new password (between 4 and 20 characters).")
    private String newPassword;

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
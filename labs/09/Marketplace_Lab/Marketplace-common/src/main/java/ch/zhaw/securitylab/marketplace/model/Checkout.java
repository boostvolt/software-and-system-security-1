package ch.zhaw.securitylab.marketplace.model;

import ch.zhaw.securitylab.marketplace.validation.CreditCardCheck;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.List;

public class Checkout {

    @NotNull(message = "First name is missing.")
    @Pattern(regexp = "^[a-zA-Z']{2,32}$",
            message = "Please insert a valid first name (between 2 and 32 characters).")
    private String firstname;
    @NotNull(message = "Last name is missing.")
    @Pattern(regexp = "^[a-zA-Z']{2,32}$",
            message = "Please insert a valid last name (between 2 and 32 characters).")
    private String lastname;
    @NotNull(message = "Credit card number is missing.")
    @CreditCardCheck
    private String creditCardNumber;
    @NotNull(message = "Product IDs are missing.")
    private List<Integer> productIDs;

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getCreditCardNumber() {
        return creditCardNumber;
    }

    public void setCreditCardNumber(String creditCardNumber) {
        this.creditCardNumber = creditCardNumber;
    }

    public List<Integer> getProductIDs() {
        return productIDs;
    }

    public void setProductIDs(List<Integer> productIDs) {
        this.productIDs = productIDs;
    }
}
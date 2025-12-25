package ch.zhaw.securitylab.marketplace.model;

import ch.zhaw.securitylab.marketplace.repository.AESConverter;
import ch.zhaw.securitylab.marketplace.validation.CreditCardCheck;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.math.BigDecimal;

@Entity
@Table(name = "Purchase")
public class Purchase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int purchaseID;
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
    @Convert(converter = AESConverter.class)
    private String creditCardNumber;
    private BigDecimal totalPrice;

    public Purchase() {}

    public Purchase(int purchaseID, String firstname, String lastname,
                    String creditCardNumber, BigDecimal totalPrice) {
        this.purchaseID = purchaseID;
        this.firstname = firstname;
        this.lastname = lastname;
        this.creditCardNumber = creditCardNumber;
        this.totalPrice = totalPrice;
    }

    public int getPurchaseID() {
        return purchaseID;
    }

    public void setPurchaseID(int purchaseID) {this.purchaseID = purchaseID; }

    public String getFirstname() { return firstname; }

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

    public BigDecimal getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(BigDecimal totalPrice) {
        this.totalPrice = totalPrice;
    }
}
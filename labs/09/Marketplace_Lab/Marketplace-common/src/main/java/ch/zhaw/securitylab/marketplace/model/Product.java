package ch.zhaw.securitylab.marketplace.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;

@Entity
@Table(name = "Product")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int productID;
    @NotNull(message = "Description is missing.")
    @Pattern(regexp = "^[a-zA-Z0-9 ,'\\-]{10,100}$",
            message = "Please insert a valid description (10-100 characters: letters / digits / - / , / ').")
    private String description;
    @NotNull(message = "Price is missing.")
    @PositiveOrZero(message = "Please insert a valid price (between 0 and 999999.99, with at most two decimal places).")
    @Digits(integer = 6, fraction = 2, message = "Please insert a valid price (between 0 and 999999.99, with at most two decimal places).")
    private BigDecimal price;
    @JsonIgnore
    private String username;

    public Product() {}

    public Product(int productID, String description, BigDecimal price, String username) {
        this.productID = productID;
        this.description = description;
        this.price = price;
        this.username = username;
    }

    public int getProductID() {
        return productID;
    }

    public void setProductID(int productID) {this.productID = productID; }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) { this.description = description; }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) { this.price = price; }

    public String getUsername() { return username; }

    public void setUsername(String username) { this.username = username; }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Product other)) {
            return false;
        }
        return productID == other.productID;
    }
}
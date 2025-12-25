package ch.zhaw.securitylab.marketplace.model;

import java.math.BigDecimal;

public class AdminProduct {

    private int productID;
    private String description;
    private BigDecimal price;
    private String username;

    public AdminProduct() {}

    public AdminProduct(Product product) {
        productID = product.getProductID();
        description = product.getDescription();
        price = product.getPrice();
        username = product.getUsername();
    }

    public int getProductID() {
        return productID;
    }

    public void setProductID(int productID) {
        this.productID = productID;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
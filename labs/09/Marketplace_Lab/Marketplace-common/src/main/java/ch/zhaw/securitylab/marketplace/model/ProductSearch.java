package ch.zhaw.securitylab.marketplace.model;

import jakarta.validation.constraints.Size;

public class ProductSearch {

    @Size(max = 50, message = "Please insert a valid search string (at most 50 characters).")
    private String description = "";

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
package ch.zhaw.securitylab.marketplace.model;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

public class Cart {

    private final List<Product> products;

    public Cart() {
        products = new ArrayList<>();
    }

    public List<Product> getProducts() {
        return products;
    }

    public boolean isEmpty() {
        return products.isEmpty();
    }

    public void clear() {
        products.clear();
    }

    public BigDecimal getTotalPrice() {
        BigDecimal total = new BigDecimal(0);
        for (Product product : products) {
            total = total.add(product.getPrice());
        }
        return total;
    }

    public void addProduct(Product product) {
        if ((product != null) && !(products.contains(product))) {
            products.add(product);
        }
    }
}
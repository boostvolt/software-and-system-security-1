package ch.zhaw.securitylab.marketplace.controller;

import ch.zhaw.securitylab.marketplace.model.*;
import ch.zhaw.securitylab.marketplace.service.ProductService;
import ch.zhaw.securitylab.marketplace.service.PurchaseService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import java.math.BigDecimal;
import java.security.InvalidParameterException;
import java.util.List;

@RestController
@RequestMapping("/rest")
public class PublicController {

    private final ProductService productService;
    private final PurchaseService purchaseService;

    public PublicController(ProductService productService, PurchaseService purchaseService) {
        this.productService = productService;
        this.purchaseService = purchaseService;
    }

    @GetMapping(value = "/public/products", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Product> getProducts(@ModelAttribute @Valid ProductSearch productSearch) {
        return productService.findByDescription(productSearch.getDescription());
    }

    @PostMapping(value = "/public/purchases", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void postPurchase(@RequestBody @Valid Checkout checkout) {
        BigDecimal totalPrice = new BigDecimal(0);
        Product product;
        int validProductIDs = 0;

        for (int productID : checkout.getProductIDs()) {
            product = productService.findById(productID);
            if (product != null) {
                totalPrice = totalPrice.add(product.getPrice());
                validProductIDs++;
            }
        }
        if (validProductIDs > 0) {
            Purchase purchase = new Purchase();
            purchase.setFirstname(checkout.getFirstname());
            purchase.setLastname(checkout.getLastname());
            purchase.setCreditCardNumber(checkout.getCreditCardNumber());
            purchase.setTotalPrice(totalPrice);
            if (!purchaseService.save(purchase)) {
                throw new RuntimeException();
            }
        } else {
            throw new InvalidParameterException(
                    "The purchase could not be completed because no valid product IDs were submitted.");
        }
    }
}
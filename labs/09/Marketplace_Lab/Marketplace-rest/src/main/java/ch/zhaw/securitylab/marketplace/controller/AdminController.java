package ch.zhaw.securitylab.marketplace.controller;

import ch.zhaw.securitylab.marketplace.model.AdminProduct;
import ch.zhaw.securitylab.marketplace.model.Product;
import ch.zhaw.securitylab.marketplace.model.Purchase;
import ch.zhaw.securitylab.marketplace.service.ProductService;
import ch.zhaw.securitylab.marketplace.service.PurchaseService;
import ch.zhaw.securitylab.marketplace.service.UtilityService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/rest")
@Validated
public class AdminController {

    private final PurchaseService purchaseService;
    private final ProductService productService;
    private final UtilityService utilityService;

    public AdminController(PurchaseService purchaseService, ProductService productService,
                           UtilityService utilityService) {
        this.purchaseService = purchaseService;
        this.productService = productService;
        this.utilityService = utilityService;
    }

    @GetMapping(value = "/admin/purchases", produces = MediaType.APPLICATION_JSON_VALUE)
    public Iterable<Purchase> getPurchases() {
        return purchaseService.findAll();
    }

    @DeleteMapping("/admin/purchases/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deletePurchase(@PathVariable(name = "id") @Min(value = 1, message = "The purchase ID must be between 1 and 999'999.")
                               @Max(value = 999999, message = "The purchase ID must be between 1 and 999'999.") int id) {
        Purchase purchase = purchaseService.findById(id);
        if (purchase != null) {
            purchaseService.delete(purchase);
        } else {
            throw new InvalidParameterException("The purchase with purchase ID = '" + id + "' does not exist.");
        }
    }

    @GetMapping(value = "/admin/products", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<AdminProduct> getProducts() {
        List<AdminProduct> adminProducts = new ArrayList<>();
        for (Product product : productService.findAll()) {
            adminProducts.add(new AdminProduct(product));
        }
        return adminProducts;
    }

    @PostMapping(value = "/admin/products", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void postProduct(@RequestBody @Valid Product product) {
        product.setUsername(utilityService.getUsernameOfAuthenticatedUser());
        if (!productService.save(product)) {
            throw new RuntimeException("Failed to save product");
        }
    }

    @DeleteMapping("/admin/products/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteProduct(@PathVariable(name = "id")
                              @Min(value = 1, message = "The product ID must be between 1 and 999'999.")
                              @Max(value = 999999, message = "The product ID must be between 1 and 999'999.") int id) {
        Product product = productService.findById(id);
        if (product == null) {
            throw new InvalidParameterException("The product with product ID = '" + id + "' does not exist.");
        }
        String currentUsername = utilityService.getUsernameOfAuthenticatedUser();
        if (!product.getUsername().equals(currentUsername)) {
            throw new AccessDeniedException("");
        }
        productService.delete(product);
    }
}
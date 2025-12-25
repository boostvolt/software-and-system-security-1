package ch.zhaw.securitylab.marketplace.controller;

import ch.zhaw.securitylab.marketplace.model.ChangePassword;
import ch.zhaw.securitylab.marketplace.model.Product;
import ch.zhaw.securitylab.marketplace.model.Purchase;
import ch.zhaw.securitylab.marketplace.service.ProductService;
import ch.zhaw.securitylab.marketplace.service.PurchaseService;
import ch.zhaw.securitylab.marketplace.service.UserService;
import ch.zhaw.securitylab.marketplace.service.UtilityService;
import jakarta.validation.Valid;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AdminController {

    private final ProductService productService;
    private final PurchaseService purchaseService;
    private final UserService userService;
    private final UtilityService utilityService;

    public AdminController(ProductService productService, PurchaseService purchaseService,
                           UserService userService, UtilityService utilityService) {
        this.productService = productService;
        this.purchaseService = purchaseService;
        this.userService = userService;
        this.utilityService = utilityService;
    }

    @GetMapping("/admin/admin")
    public String adminPage(Model model) {
        String role = utilityService.getRoleOfAuthenticatedUser();
        if (role.equals("MARKETING") || role.equals("SALES")) {
            Iterable<Purchase> purchases = purchaseService.findAll();
            model.addAttribute("purchases", purchases);
        } else if (role.equals("PRODUCTMANAGER")) {
            Iterable<Product> products = productService.findAll();
            model.addAttribute("products", products);
            model.addAttribute("username", utilityService.getUsernameOfAuthenticatedUser());
        }
        return "admin/admin";
    }

    @PostMapping("/admin/deletepurchase/{id}")
    public String deletePurchase(@PathVariable(name = "id") int id) {
        Purchase purchase = purchaseService.findById(id);
        if (purchase != null) {
            purchaseService.delete(purchase);
        }
        return "redirect:/admin/admin";
    }

    @PostMapping("/admin/deleteproduct/{id}")
    public String deleteProduct(@PathVariable(name = "id") int id) {
        Product product = productService.findById(id);
        if (product != null) {
            String currentUsername = utilityService.getUsernameOfAuthenticatedUser();
            if (!product.getUsername().equals(currentUsername)) {
                throw new AccessDeniedException("");
            }
            productService.delete(product);
        }
        return "redirect:/admin/admin";
    }

    @GetMapping("/admin/addproduct")
    public String addProductPage(Model model) {
        Product product = new Product();
        model.addAttribute("product", product);
        return "admin/addproduct";
    }

    @PostMapping("/admin/saveproduct")
    public String saveProduct(@ModelAttribute @Valid Product product, BindingResult bindingResult,
                              Model model, RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("product", product);
            return "admin/addproduct";
        } else {
            product.setUsername(utilityService.getUsernameOfAuthenticatedUser());
            productService.save(product);
            redirectAttributes.addFlashAttribute("message", "The product could successfully be added.");
            return "redirect:/admin/admin";
        }
    }

    @GetMapping("/admin/accountsettings")
    public String accountSettingsPage(Model model) {
        model.addAttribute("username", utilityService.getUsernameOfAuthenticatedUser());
        ChangePassword changePassword = new ChangePassword();
        model.addAttribute("changePassword", changePassword);
        return "admin/accountsettings";
    }

    @PostMapping("/admin/changepassword")
    public String changePassword(@ModelAttribute @Valid ChangePassword changePassword,
                                 BindingResult bindingResult,
                                 Model model, RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("username", utilityService.getUsernameOfAuthenticatedUser());
            model.addAttribute("changePassword", changePassword);
            return "admin/accountsettings";
        } else {
            String message;
            if (userService.changePassword(utilityService.getUsernameOfAuthenticatedUser(), changePassword)) {
                message = "The password could successfully be changed.";
            } else {
                message = "The password could not be changed.";
            }
            redirectAttributes.addFlashAttribute("message", message);
            return "redirect:/admin/accountsettings";
        }
    }
}
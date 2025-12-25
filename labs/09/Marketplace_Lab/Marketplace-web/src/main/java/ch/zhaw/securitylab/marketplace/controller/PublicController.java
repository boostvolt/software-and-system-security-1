package ch.zhaw.securitylab.marketplace.controller;

import ch.zhaw.securitylab.marketplace.model.*;
import ch.zhaw.securitylab.marketplace.service.ProductService;
import ch.zhaw.securitylab.marketplace.service.PurchaseService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Controller
public class PublicController {

    private final ProductService productService;
    private final PurchaseService purchaseService;

    public PublicController(ProductService productService, PurchaseService purchaseService) {
        this.productService = productService;
        this.purchaseService = purchaseService;
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/public/products";
    }

    @GetMapping("/public/products")
    public String productsPage(@ModelAttribute @Valid ProductSearch productSearch, BindingResult bindingResult,
                               @RequestParam(value = "logout", required = false) String logout, Model model) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("products", new ArrayList<Product>());
            productSearch.setDescription("");
            model.addAttribute("productSearch", productSearch);
        } else {
            List<Product> products = productService.findByDescription(productSearch.getDescription());
            model.addAttribute("products", products);
            model.addAttribute("productSearch", productSearch);
            if (logout != null) {
                model.addAttribute("message", "You have been logged out.");
            }
        }
        return "public/products";
    }

    @PostMapping("/public/addtocart/{id}")
    public String addToCart(@PathVariable(name = "id") int id, HttpSession session) {
        Cart cart = getCartFromSession(session);
        Product product = productService.findById(id);
        if (product != null) {
            cart.addProduct(product);
        }
        return "redirect:/public/cart";
    }

    @GetMapping("/public/cart")
    public String cartPage(Model model, HttpSession session) {
        Cart cart = getCartFromSession(session);
        model.addAttribute("products", cart.getProducts());
        return "public/cart";
    }

    @GetMapping("/public/checkout")
    public String checkoutPage(Model model, HttpSession session) {
        Cart cart = getCartFromSession(session);
        model.addAttribute("products", cart.getProducts());
        Purchase purchase = new Purchase();
        model.addAttribute("purchase", purchase);
        return "public/checkout";
    }

    @PostMapping("/public/purchase")
    public String savePurchase(@ModelAttribute @Valid Purchase purchase, BindingResult bindingResult,
                               Model model, HttpSession session, RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            Cart cart = getCartFromSession(session);
            model.addAttribute("products", cart.getProducts());
            model.addAttribute("purchase", purchase);
            return "public/checkout";
        } else {
            Cart cart = getCartFromSession(session);
            if (cart.isEmpty()) {
                redirectAttributes.addFlashAttribute("message", "Your purchase could not be completed as the shopping cart is empty.");
            } else {
                BigDecimal totalPrice = cart.getTotalPrice();
                purchase.setTotalPrice(totalPrice);
                String message;
                if (purchaseService.save(purchase)) {
                    message = "Your purchase has been completed, thank you for shopping with us.";
                } else {
                    message = "Something went wrong, please try again later.";
                }
                cart.clear();
                redirectAttributes.addFlashAttribute("message", message);
            }
            return "redirect:/public/products";
        }
    }

    @GetMapping("/public/login")
    public String loginPage(Model model) {
        model.addAttribute("credentials", new Credentials());
        return "public/login";
    }

    @PostMapping("/public/login-check")
    public String processLogin(@ModelAttribute @Valid Credentials credentials,
                               BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("credentials", credentials);
            return "public/login";
        }

        // Forward to Spring Security's real login endpoint
        return "forward:/public/login";
    }

    @GetMapping("/public/attacks")
    public String attacksPage() {
        return "public/attacks";
    }

    private Cart getCartFromSession(HttpSession session) {
        Cart cart = (Cart) session.getAttribute("cart");
        if (cart == null) {
            cart = new Cart();
            session.setAttribute("cart", cart);
        }
        return cart;
    }
}
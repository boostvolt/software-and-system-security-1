package ch.zhaw.securitylab.marketplace.service;

import ch.zhaw.securitylab.marketplace.model.Product;
import ch.zhaw.securitylab.marketplace.repository.ProductRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class ProductService {

    private final ProductRepository repo;

    public ProductService(ProductRepository repo) {
        this.repo = repo;
    }

    public Iterable<Product> findAll() {
        return repo.findAll();
    }

    public Product findById(int id) {
        Optional<Product> product = repo.findById(id);
        if (product.isPresent()) {
            return product.get();
        } else {
            return null;
        }
    }

    public List<Product> findByDescription(String description) {
        return repo.findByDescriptionContaining(description);
    }

    public boolean save(Product product) {
        try  {
            repo.save(product);
            return true;
        } catch (DataAccessException e) {
            return false;
        }
    }

    public boolean delete(Product product) {
        try  {
            repo.delete(product);
            return true;
        } catch (DataAccessException e) {
            return false;
        }
    }
}
package ch.zhaw.securitylab.marketplace.repository;

import ch.zhaw.securitylab.marketplace.model.Product;
import org.springframework.data.repository.CrudRepository;
import java.util.List;

public interface ProductRepository extends CrudRepository<Product, Integer> {

    List<Product> findByDescriptionContaining(String description);
}
package ch.zhaw.securitylab.marketplace.repository;

import ch.zhaw.securitylab.marketplace.model.Purchase;
import org.springframework.data.repository.CrudRepository;

public interface PurchaseRepository extends CrudRepository<Purchase, Integer> {}
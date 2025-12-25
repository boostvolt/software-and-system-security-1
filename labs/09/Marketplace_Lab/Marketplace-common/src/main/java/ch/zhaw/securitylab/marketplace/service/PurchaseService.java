package ch.zhaw.securitylab.marketplace.service;

import ch.zhaw.securitylab.marketplace.repository.PurchaseRepository;
import ch.zhaw.securitylab.marketplace.model.Purchase;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class PurchaseService {

    private final PurchaseRepository repo;

    public PurchaseService(PurchaseRepository repo) {
        this.repo = repo;
    }

    public Iterable<Purchase> findAll() {
        return repo.findAll();
    }

    public Purchase findById(int id) {
        Optional<Purchase> purchase = repo.findById(id);
        if (purchase.isPresent()) {
            return purchase.get();
        } else {
            return null;
        }
    }

    public boolean save(Purchase purchase) {
        try  {
            repo.save(purchase);
            return true;
        } catch (DataAccessException e) {
            return false;
        }
    }

    public boolean delete(Purchase purchase) {
        try  {
            repo.delete(purchase);
            return true;
        } catch (DataAccessException e) {
            return false;
        }
    }
}
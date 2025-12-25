package ch.zhaw.securitylab.marketplace.repository;

import ch.zhaw.securitylab.marketplace.model.User;
import org.springframework.data.repository.CrudRepository;
import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Integer> {

    Optional<User> findByUsername(String username);
}
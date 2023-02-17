package pl.mimuw.carrentalback.data;

import org.springframework.data.repository.CrudRepository;
import pl.mimuw.carrentalback.entity.User;

public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}

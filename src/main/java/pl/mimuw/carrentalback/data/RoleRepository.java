package pl.mimuw.carrentalback.data;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import pl.mimuw.carrentalback.models.ERole;
import pl.mimuw.carrentalback.models.Role;

import java.util.Optional;

@Repository
public interface RoleRepository extends CrudRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}

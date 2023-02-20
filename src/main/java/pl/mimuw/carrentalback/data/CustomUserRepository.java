package pl.mimuw.carrentalback.data;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Repository;
import pl.mimuw.carrentalback.models.User;

@Repository
public class CustomUserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Transactional
    public User update(User user) {
        entityManager.merge(user);
        return user;
    }

    @Transactional
    public User findById(long id) {
        return entityManager.find(User.class, id);
    }

}

package pl.mimuw.carrentalback.data;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.User;
import pl.mimuw.carrentalback.models.UserCar;

import java.util.Optional;

@Repository
public interface UserCarRepository extends CrudRepository<UserCar, Long> {

    Optional<UserCar> findUserCarByUserAndCar(User user, Car car);
}

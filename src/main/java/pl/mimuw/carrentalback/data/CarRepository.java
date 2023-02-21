package pl.mimuw.carrentalback.data;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import pl.mimuw.carrentalback.models.Car;

import java.util.List;

public interface CarRepository extends JpaRepository<Car, Long> {

    @Query("SELECT c FROM Car c WHERE c.id NOT IN (SELECT uc.car.id FROM UserCar uc)")
    List<Car> findAllNotInUserCar();
}

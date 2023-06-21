package pl.mimuw.carrentalback.data;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import pl.mimuw.carrentalback.models.Car;

import java.util.List;

public interface CarRepository extends JpaRepository<Car, Long> {

    @Query("SELECT c FROM Car c WHERE c.id NOT IN (SELECT uc.car.id FROM UserCar uc)")
    List<Car> findAllNotInUserCar();

    @Query("SELECT c, uc.startDate, uc.endDate FROM Car c LEFT JOIN c.users uc ON c.id = uc.car.id WHERE uc.user.username = :username")
    List<Object> findAllRentedCarsByUsername(@Param("username") String username);
}

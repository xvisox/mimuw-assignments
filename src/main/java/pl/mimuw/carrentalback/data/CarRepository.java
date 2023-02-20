package pl.mimuw.carrentalback.data;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.mimuw.carrentalback.models.Car;

public interface CarRepository extends JpaRepository<Car, Long> {
}

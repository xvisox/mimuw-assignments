package pl.mimuw.carrentalback.services;

import lombok.Data;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.CarRepository;
import pl.mimuw.carrentalback.models.Car;

import java.util.List;
import java.util.Optional;

@Data
@Service
public class CarService {
    private final CarRepository carRepository;

    public Optional<Car> getCarById(Long id) {
        return carRepository.findById(id);
    }

    public List<Car> getOffers() {
        return carRepository.findAll();
    }
}

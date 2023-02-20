package pl.mimuw.carrentalback.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.CarRepository;
import pl.mimuw.carrentalback.models.Car;

import java.util.List;

@Service
public class OfferService {
    private final CarRepository carRepository;

    @Autowired
    public OfferService(CarRepository carRepository) {
        this.carRepository = carRepository;
    }

    public List<Car> getOffers() {
        return carRepository.findAll();
    }
}

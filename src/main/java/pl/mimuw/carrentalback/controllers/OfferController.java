package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.payload.request.RentRequest;
import pl.mimuw.carrentalback.services.CarService;
import pl.mimuw.carrentalback.services.RentalService;

import java.util.List;

@Data
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/offer")
public class OfferController {
    private final CarService carService;
    private final RentalService rentalService;

    @GetMapping
    public ResponseEntity<List<Car>> getAllOffers() {
        List<Car> cars = carService.getOffers();
        return ResponseEntity.ok(cars);
    }

    @PostMapping("/rent")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Car> rentCar(@RequestBody RentRequest rentRequest) {
        // Car to rent.
        Car car = carService.getCarById(rentRequest.getCarId()).orElse(null);
        if (car == null) return new ResponseEntity<>(HttpStatus.BAD_REQUEST);

        // Try to rent the car for the user.
        boolean success = rentalService.rentCar(rentRequest.getUsername(), car);
        if (!success) return new ResponseEntity<>(HttpStatus.BAD_REQUEST);

        return new ResponseEntity<>(null, HttpStatus.CREATED);
    }
}

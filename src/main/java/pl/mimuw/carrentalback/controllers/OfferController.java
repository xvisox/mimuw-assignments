package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.RentedCar;
import pl.mimuw.carrentalback.payload.request.MyCarsRequest;
import pl.mimuw.carrentalback.payload.request.RentRequest;
import pl.mimuw.carrentalback.services.RentalService;

import java.text.ParseException;
import java.util.List;

@Data
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/offer")
public class OfferController {
    private final RentalService rentalService;

    @GetMapping
    public ResponseEntity<List<Car>> getAllCars() {
        List<Car> cars = rentalService.getOffers();
        return ResponseEntity.ok(cars);
    }

    @PostMapping("/my")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<RentedCar>> getMyCars(@RequestBody MyCarsRequest request) {
        List<RentedCar> cars = rentalService.getMyOffers(request.getUsername());
        return ResponseEntity.ok(cars);
    }
}

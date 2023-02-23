package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.RentedCar;
import pl.mimuw.carrentalback.services.RentalService;

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

    @GetMapping("/my")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<RentedCar>> getMyCars() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        List<RentedCar> cars = rentalService.getMyOffers(auth.getName());
        return ResponseEntity.ok(cars);
    }
}

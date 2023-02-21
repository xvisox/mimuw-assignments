package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pl.mimuw.carrentalback.models.Car;
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
    public ResponseEntity<List<Car>> getAllOffers() {
        List<Car> cars = rentalService.getOffers();
        return ResponseEntity.ok(cars);
    }

    @PostMapping("/rent")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Car> rentCar(@RequestBody RentRequest rentRequest) {
        try {
            boolean success = rentalService.rentCar(rentRequest);
            if (!success) {
                return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
            } else {
                return new ResponseEntity<>(null, HttpStatus.CREATED);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }
}

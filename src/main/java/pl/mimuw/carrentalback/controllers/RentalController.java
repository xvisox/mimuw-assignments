package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.payload.request.ExtendRequest;
import pl.mimuw.carrentalback.payload.request.RentRequest;
import pl.mimuw.carrentalback.payload.request.ReturnRequest;
import pl.mimuw.carrentalback.services.RentalService;

import java.text.ParseException;

@Data
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/rental")
public class RentalController {
    private final RentalService rentalService;

    @PostMapping("/rent")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Object> rentCar(@RequestBody RentRequest rentRequest) {
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

    @PatchMapping("/extend")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Object> extendRental(@RequestBody ExtendRequest request) {
        try {
            boolean success = rentalService.extendRental(request);
            if (!success) {
                return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
            } else {
                return new ResponseEntity<>(null, HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/return")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Object> returnCar(@RequestBody ReturnRequest request) {
        boolean success = rentalService.returnCar(request);
        if (!success) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        } else {
            return new ResponseEntity<>(null, HttpStatus.OK);
        }
    }
}

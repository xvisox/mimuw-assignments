package pl.mimuw.carrentalback.controllers;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
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
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean success = rentRequest.getUsername().equals(auth.getName()) && rentalService.rentCar(rentRequest);
            if (!success) {
                return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
            } else {
                return new ResponseEntity<>(null, HttpStatus.CREATED);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    @PatchMapping("/extend/{id}/days/{days}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Object> extendRental(@PathVariable Long id, @PathVariable Long days) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean success = rentalService.extendRental(new ExtendRequest(auth.getName(), id, days));
            if (!success) {
                return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
            } else {
                return new ResponseEntity<>(null, HttpStatus.OK);
            }
        } catch (ParseException e) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/return/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Object> returnCar(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean success = rentalService.returnCar(new ReturnRequest(auth.getName(), id));
        if (!success) {
            return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        } else {
            return new ResponseEntity<>(null, HttpStatus.OK);
        }
    }
}

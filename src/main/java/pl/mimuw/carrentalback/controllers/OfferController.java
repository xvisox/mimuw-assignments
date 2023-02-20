package pl.mimuw.carrentalback.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.services.OfferService;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/offer")
public class OfferController {
    private final OfferService offerService;

    @Autowired
    public OfferController(OfferService offerService) {
        this.offerService = offerService;
    }

    @GetMapping
    public ResponseEntity<List<Car>> getAllOffers() {
        List<Car> cars = offerService.getOffers();
        return ResponseEntity.ok(cars);
    }
}

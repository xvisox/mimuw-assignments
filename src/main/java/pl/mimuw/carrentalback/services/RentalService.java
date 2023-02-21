package pl.mimuw.carrentalback.services;

import lombok.Data;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.UserRepository;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.User;

@Service
@Data
public class RentalService {
    private final UserRepository userRepo;

    public boolean rentCar(String username, Car carToRent) {
        User user = userRepo.findByUsername(username).orElse(null);
        if (user == null) return false;

        user.getRentedCars().add(carToRent);
        userRepo.save(user);
        return true;
    }
}

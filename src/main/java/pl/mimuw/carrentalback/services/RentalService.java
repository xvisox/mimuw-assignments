package pl.mimuw.carrentalback.services;

import lombok.Data;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.UserRepository;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.User;
import pl.mimuw.carrentalback.models.UserCar;

import java.util.Date;

@Service
@Data
public class RentalService {
    private final UserRepository userRepo;

    public boolean rentCar(String username, Car carToRent) {
        User user = userRepo.findByUsername(username).orElse(null);
        if (user == null) return false;

        UserCar userCar = new UserCar(user, carToRent, new Date());
        user.getRentedCars().add(userCar);
        userRepo.save(user);
        return true;
    }
}

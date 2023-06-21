package pl.mimuw.carrentalback.services;

import lombok.Data;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.UserRepository;
import pl.mimuw.carrentalback.models.User;

@Data
@Service
public class ProfileInfoService {
    private final UserRepository userRepo;

    public User getUserInfo(String username) {
        return userRepo.findByUsername(username).orElse(null);
    }
}

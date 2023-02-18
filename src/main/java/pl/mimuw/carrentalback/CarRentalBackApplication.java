package pl.mimuw.carrentalback;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import pl.mimuw.carrentalback.data.RoleRepository;
import pl.mimuw.carrentalback.models.ERole;
import pl.mimuw.carrentalback.models.Role;

@SpringBootApplication
public class CarRentalBackApplication {

    public static void main(String[] args) {
        SpringApplication.run(CarRentalBackApplication.class, args);
    }

    @Bean
    public ApplicationRunner dataLoader(RoleRepository repo) {
        return args -> {
            repo.save(new Role(ERole.ROLE_USER));
            repo.save(new Role(ERole.ROLE_MODERATOR));
            repo.save(new Role(ERole.ROLE_ADMIN));
        };
    }
}

package pl.mimuw.carrentalback.data;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.ERole;
import pl.mimuw.carrentalback.models.Role;
import pl.mimuw.carrentalback.models.User;

@Component
public class DataLoader implements ApplicationRunner {
    private final CarRepository repo;
    private final RoleRepository roleRepo;
    private final UserRepository userRepo;
    private final CustomUserRepository customRepo;
    private final PasswordEncoder encoder;

    @Autowired
    public DataLoader(CarRepository repo, RoleRepository roleRepo, UserRepository userRepo,
                      CustomUserRepository customRepo, PasswordEncoder encoder) {
        this.repo = repo;
        this.roleRepo = roleRepo;
        this.userRepo = userRepo;
        this.customRepo = customRepo;
        this.encoder = encoder;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // ROLES.
        roleRepo.save(new Role(ERole.ROLE_USER));
        roleRepo.save(new Role(ERole.ROLE_MODERATOR));
        roleRepo.save(new Role(ERole.ROLE_ADMIN));

        // USERS.
        User admin = new User("user", "user@gmail.com", encoder.encode("du@8aXPRiUPM"));
        admin.getRoles().add(roleRepo.findByName(ERole.ROLE_USER).orElse(null));
        userRepo.save(admin);

        // UPDATE USER example.
        // User user = customRepo.findById(1L);
        // Role adminRole = roleRepo.findByName(ERole.ROLE_ADMIN).orElse(null);
        // user.getRoles().add(adminRole);
        // customRepo.update(user);

        // CARS.
        repo.save(new Car("Audi", "Q3", 419, 2019, "Semi-Auto", "Standard", 200));
        repo.save(new Car("Audi", "Q5", 454, 2019, "Semi-Auto", "Standard", 220));
        repo.save(new Car("Audi", "Q3", 564, 2020, "Semi-Auto", "Standard", 300));
        repo.save(new Car("Audi", "Q7", 262, 2017, "Automatic", "Premium", 150));
        repo.save(new Car("Audi", "A5", 437, 2019, "Manual", "Standard", 210));
        repo.save(new Car("Audi", "Q5", 489, 2019, "Semi-Auto", "Standard", 230));
        repo.save(new Car("Audi", "Q7", 402, 2019, "Automatic", "Premium", 270));
        repo.save(new Car("Audi", "A5", 580, 2020, "Semi-Auto", "Standard", 310));
        repo.save(new Car("Audi", "TT", 195, 2016, "Semi-Auto", "Standard", 100));
        repo.save(new Car("Audi", "TT", 405, 2019, "Manual", "Standard", 190));
        repo.save(new Car("Audi", "Q7", 462, 2019, "Automatic", "Standard", 220));
        repo.save(new Car("Audi", "Q3", 451, 2019, "Automatic", "Standard", 210));
        repo.save(new Car("Audi", "Q7", 567, 2020, "Semi-Auto", "Standard", 300));
        repo.save(new Car("Audi", "Q7", 270, 2017, "Automatic", "Standard", 110));
        repo.save(new Car("Audi", "Q3", 472, 2019, "Automatic", "Standard", 220));
        repo.save(new Car("Audi", "Q7", 267, 2017, "Automatic", "Standard", 110));
        repo.save(new Car("Audi", "Q7", 373, 2018, "Semi-Auto", "Premium", 220));
        repo.save(new Car("Audi", "A5", 596, 2020, "Semi-Auto", "Standard", 320));
        repo.save(new Car("Audi", "A6", 475, 2019, "Automatic", "Standard", 230));
        repo.save(new Car("Audi", "Q7", 210, 2015, "Automatic", "Standard", 100));
        repo.save(new Car("Audi", "S4", 442, 2019, "Automatic", "Standard", 210));
        repo.save(new Car("Audi", "Q7", 157, 2016, "Automatic", "Standard", 100));
        repo.save(new Car("Audi", "A6", 437, 2019, "Automatic", "Standard", 210));
        repo.save(new Car("Audi", "Q7", 315, 2018, "Automatic", "Premium", 180));
        repo.save(new Car("Audi", "Q7", 519, 2020, "Semi-Auto", "Premium", 380));
        repo.save(new Car("BMW", "X5", 529, 2019, "Automatic", "Premium", 350));
        repo.save(new Car("BMW", "Z4", 616, 2020, "Semi-Auto", "Standard", 330));
        repo.save(new Car("BMW", "M4", 547, 2019, "Automatic", "Standard", 260));
        repo.save(new Car("BMW", "5 Series", 344, 2017, "Semi-Auto", "Standard", 140));
        repo.save(new Car("BMW", "5 Series", 521, 2019, "Automatic", "Standard", 250));
        repo.save(new Car("BMW", "M6", 242, 2016, "Semi-Auto", "Standard", 100));
        repo.save(new Car("BMW", "7 Series", 571, 2019, "Semi-Auto", "Standard", 270));
        repo.save(new Car("BMW", "X5", 485, 2019, "Automatic", "Premium", 320));
        repo.save(new Car("BMW", "M4", 255, 2016, "Semi-Auto", "Standard", 110));
        repo.save(new Car("BMW", "X3", 588, 2019, "Automatic", "Standard", 280));
        repo.save(new Car("BMW", "X5", 237, 2016, "Automatic", "Standard", 100));
        repo.save(new Car("BMW", "3 Series", 561, 2019, "Semi-Auto", "Standard", 270));
        repo.save(new Car("BMW", "X5", 524, 2019, "Automatic", "Standard", 250));
        repo.save(new Car("BMW", "2 Series", 428, 2018, "Semi-Auto", "Standard", 180));
        repo.save(new Car("BMW", "7 Series", 371, 2017, "Semi-Auto", "Standard", 160));
        repo.save(new Car("BMW", "M4", 423, 2018, "Semi-Auto", "Premium", 250));
        repo.save(new Car("BMW", "4 Series", 653, 2020, "Automatic", "Standard", 350));
        repo.save(new Car("BMW", "Z4", 658, 2020, "Semi-Auto", "Standard", 350));
        repo.save(new Car("BMW", "M4", 303, 2019, "Semi-Auto", "Standard", 140));
        repo.save(new Car("BMW", "3 Series", 484, 2019, "Automatic", "Standard", 230));
        repo.save(new Car("BMW", "5 Series", 386, 2019, "Automatic", "Standard", 180));
        repo.save(new Car("BMW", "3 Series", 621, 2020, "Semi-Auto", "Standard", 330));
        repo.save(new Car("BMW", "X4", 567, 2019, "Semi-Auto", "Standard", 270));
        repo.save(new Car("BMW", "8 Series", 496, 2019, "Semi-Auto", "Premium", 330));
        repo.save(new Car("BMW", "4 Series", 514, 2019, "Automatic", "Standard", 250));
        repo.save(new Car("Mercedes-Benz", "C300", 451, 2019, "Semi-Auto", "Standard", 210));
        repo.save(new Car("Mercedes-Benz", "E53", 538, 2020, "Automatic", "Premium", 400));
        repo.save(new Car("Mercedes-Benz", "GLE", 489, 2019, "Semi-Auto", "Premium", 330));
        repo.save(new Car("Mercedes-Benz", "C200", 349, 2019, "Automatic", "Standard", 170));
        repo.save(new Car("Mercedes-Benz", "SL Class", 180, 2016, "Semi-Auto", "Premium", 100));
        repo.save(new Car("Mercedes-Benz", "E43", 406, 2019, "Automatic", "Standard", 190));
        repo.save(new Car("Mercedes-Benz", "C43", 403, 2019, "Automatic", "Premium", 270));
        repo.save(new Car("Mercedes-Benz", "C63S", 508, 2020, "Semi-Auto", "Standard", 270));
        repo.save(new Car("Mercedes-Benz", "A45", 481, 2019, "Automatic", "Standard", 230));
        repo.save(new Car("Mercedes-Benz", "S63", 530, 2015, "Automatic", "Premium", 310));
        repo.save(new Car("Mercedes-Benz", "GL Class", 121, 2016, "Semi-Auto", "Standard", 100));
        repo.save(new Car("Mercedes-Benz", "V Class", 421, 2019, "Automatic", "Standard", 200));
        repo.save(new Car("Mercedes-Benz", "GLE Class", 555, 2020, "Automatic", "Premium", 410));
        repo.save(new Car("Mercedes-Benz", "A45", 354, 2018, "Automatic", "Premium", 210));
        repo.save(new Car("Mercedes-Benz", "CLA45", 474, 2019, "Semi-Auto", "Standard", 230));
        repo.save(new Car("Mercedes-Benz", "S500", 489, 2019, "Automatic", "Supercar", 390));
        repo.save(new Car("Mercedes-Benz", "E53", 431, 2019, "Semi-Auto", "Standard", 200));
        repo.save(new Car("Mercedes-Benz", "SL CLASS", 152, 2016, "Automatic", "Standard", 100));
        repo.save(new Car("Mercedes-Benz", "S43", 472, 2019, "Semi-Auto", "Premium", 310));
        repo.save(new Car("Mercedes-Benz", "A35", 492, 2019, "Automatic", "Premium", 330));
        repo.save(new Car("Mercedes-Benz", "E43", 424, 2019, "Semi-Auto", "Standard", 200));
        repo.save(new Car("Mercedes-Benz", "GTR", 731, 2019, "Semi-Auto", "Standard", 350));
        repo.save(new Car("Mercedes-Benz", "V Class", 481, 2019, "Semi-Auto", "Standard", 230));
        repo.save(new Car("Mercedes-Benz", "GLE", 473, 2019, "Automatic", "Standard", 230));
        repo.save(new Car("Mercedes-Benz", "CLA35", 336, 2018, "Semi-Auto", "Supercar", 240));
        repo.save(new Car("Ferrari", "F8", 710, 2021, "Automatic", "Supercar", 700));
        repo.save(new Car("Porsche", "Panamera", 440, 2022, "Automatic", "Supercar", 470));
        repo.save(new Car("Bugatti", "Chiron", 1510, 2022, "Automatic", "Supercar", 1630));
        repo.save(new Car("Lamborghini", "Aventador", 769, 2020, "Automatic", "Supercar", 690));
        repo.save(new Car("Maserati", "GTR", 454, 2020, "Automatic", "Supercar", 400));
        repo.save(new Car("Aston Martin", "DBX", 542, 2018, "Automatic", "Supercar", 390));
        repo.save(new Car("McLaren", "720S", 710, 2019, "Automatic", "Supercar", 570));
        repo.save(new Car("Lamborghini", "Urus", 657, 2021, "Automatic", "Supercar", 650));
        repo.save(new Car("Rolls-Royce", "Phantom", 563, 2019, "Automatic", "Supercar", 450));
        repo.save(new Car("Ferrari", "Roma", 612, 2021, "Automatic", "Supercar", 600));
        repo.save(new Car("Tesla", "Model S", 670, 2018, "Automatic", "Electric", 320));
        repo.save(new Car("Tesla", "Model 3", 283, 2019, "Automatic", "Electric", 150));
        repo.save(new Car("Tesla", "Model X", 670, 2020, "Automatic", "Electric", 400));
        repo.save(new Car("Tesla", "Model Y", 384, 2021, "Automatic", "Electric", 250));
    }
}

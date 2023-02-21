package pl.mimuw.carrentalback.services;

import lombok.Data;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.CarRepository;
import pl.mimuw.carrentalback.data.UserRepository;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.User;
import pl.mimuw.carrentalback.models.UserCar;
import pl.mimuw.carrentalback.payload.request.RentRequest;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

@Service
@Data
public class RentalService {
    private final UserRepository userRepo;
    private final CarRepository carRepo;

    public List<Car> getOffers() {
        return carRepo.findAllNotInUserCar();
    }

    public boolean rentCar(RentRequest request) throws ParseException {
        Car car = carRepo.findById(request.getCarId()).orElse(null);
        User user = userRepo.findByUsername(request.getUsername()).orElse(null);
        if (user == null || car == null) return false;

        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);
        Date startDate = formatter.parse(request.getStartDate());
        Date endDate = formatter.parse(request.getEndDate());

        UserCar userCar = new UserCar(user, car, startDate, endDate);
        user.getRentedCars().add(userCar);

        Long moneySpent = getDifferenceDays(startDate, endDate) * car.getPrice();
        user.addMoneySpent(moneySpent);

        userRepo.save(user);
        return true;
    }

    private Long getDifferenceDays(Date start, Date end) {
        long diff = end.getTime() - start.getTime();
        return TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
    }
}

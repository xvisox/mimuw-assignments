package pl.mimuw.carrentalback.services;

import lombok.Data;
import org.springframework.stereotype.Service;
import pl.mimuw.carrentalback.data.CarRepository;
import pl.mimuw.carrentalback.data.UserCarRepository;
import pl.mimuw.carrentalback.data.UserRepository;
import pl.mimuw.carrentalback.models.Car;
import pl.mimuw.carrentalback.models.RentedCar;
import pl.mimuw.carrentalback.models.User;
import pl.mimuw.carrentalback.models.UserCar;
import pl.mimuw.carrentalback.payload.request.ExtendRequest;
import pl.mimuw.carrentalback.payload.request.RentRequest;
import pl.mimuw.carrentalback.payload.request.ReturnRequest;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

@Service
@Data
public class RentalService {
    private final UserRepository userRepo;
    private final CarRepository carRepo;
    private final UserCarRepository userCarRepo;
    private final static long DAY = 24 * 60 * 60 * 1000;

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

    public List<RentedCar> getMyOffers(String username) {
        List<Object> result = carRepo.findAllRentedCarsByUsername(username);

        List<RentedCar> cars = new ArrayList<>();
        for (Object o : result) {
            Object[] arr = (Object[]) o;
            Car car = (Car) arr[0];
            Date startDate = (Date) arr[1];
            Date endDate = (Date) arr[2];
            cars.add(new RentedCar(car, startDate, endDate));
        }
        return cars;
    }

    public boolean extendRental(ExtendRequest request) {
        User user = userRepo.findByUsername(request.getUsername()).orElse(null);
        Car car = carRepo.findById(request.getCarId()).orElse(null);
        if (user == null || car == null) return false;

        UserCar userCar = userCarRepo.findUserCarByUserAndCar(user, car).orElse(null);
        if (userCar == null) return false;

        Date newEndDate = new Date(userCar.getEndDate().getTime() + request.getDays() * DAY);
        userCar.setEndDate(newEndDate);

        Long moneySpent = request.getDays() * car.getPrice();
        user.addMoneySpent(moneySpent);

        userCarRepo.save(userCar);
        userRepo.save(user);
        return true;
    }

    public boolean returnCar(ReturnRequest request) {
        User user = userRepo.findByUsername(request.getUsername()).orElse(null);
        Car car = carRepo.findById(request.getCarId()).orElse(null);
        if (user == null || car == null) return false;

        UserCar userCar = userCarRepo.findUserCarByUserAndCar(user, car).orElse(null);
        if (userCar == null) return false;

        user.getRentedCars().remove(userCar);
        userCarRepo.delete(userCar);
        userRepo.save(user);
        return true;
    }
}

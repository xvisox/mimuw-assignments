package pl.mimuw.carrentalback.models;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class RentedCar {
    private Car car;
    private Date startDate;
    private Date endDate;
}

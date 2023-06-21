package pl.mimuw.carrentalback.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import pl.mimuw.carrentalback.models.Car;

import java.util.Date;

@Data
@AllArgsConstructor
public class RentedCarResponse {
    private Long id;
    private String brand;
    private String model;
    private Integer year;
    private Integer price;
    private Date startDate;
    private Date endDate;

    public RentedCarResponse(Car car, Date startDate, Date endDate) {
        this.id = car.getId();
        this.brand = car.getBrand();
        this.model = car.getModel();
        this.year = car.getYear();
        this.price = car.getPrice();
        this.startDate = startDate;
        this.endDate = endDate;
    }
}

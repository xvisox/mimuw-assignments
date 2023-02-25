package pl.mimuw.carrentalback.payload.request;

import lombok.Data;

@Data
public class RentRequest {
    private String username;
    private Long carId;
    // Rental period.
    private String startDate;
    private String endDate;
}

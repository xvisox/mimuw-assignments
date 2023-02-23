package pl.mimuw.carrentalback.payload.request;

import lombok.Data;

@Data
public class ReturnRequest {
    private String username;
    private Long carId;
}

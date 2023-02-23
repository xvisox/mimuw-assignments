package pl.mimuw.carrentalback.payload.request;

import lombok.Data;

@Data
public class ExtendRequest {
    private String username;
    private Long carId;
    private Long days;
}

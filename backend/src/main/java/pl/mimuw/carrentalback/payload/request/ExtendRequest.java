package pl.mimuw.carrentalback.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ExtendRequest {
    private String username;
    private Long carId;
    private Long days;
}

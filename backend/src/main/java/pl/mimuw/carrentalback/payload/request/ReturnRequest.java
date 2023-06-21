package pl.mimuw.carrentalback.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ReturnRequest {
    private String username;
    private Long carId;
}

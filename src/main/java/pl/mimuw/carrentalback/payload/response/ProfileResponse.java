package pl.mimuw.carrentalback.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import pl.mimuw.carrentalback.models.User;

@Data
@AllArgsConstructor
public class ProfileResponse {
    private User user;
    // Order history in the future...
}

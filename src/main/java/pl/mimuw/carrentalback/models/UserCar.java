package pl.mimuw.carrentalback.models;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Entity
@NoArgsConstructor
@EqualsAndHashCode(exclude = {"user", "car"})
public class UserCar {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "car_id")
    private Car car;

    // Car rental period.
    private Date startDate;
    private Date endDate;

    public UserCar(User user, Car carToRent, Date date) {
        this.user = user;
        this.car = carToRent;
        this.endDate = date;
    }
}

package pl.mimuw.carrentalback.models;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "cars")
@Data
@NoArgsConstructor
public class Car {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String brand;
    private String model;
    private Integer horsepower;
    private Integer year;
    private String gearbox;
    private String category;
    private Integer price;

    public Car(String brand, String model, Integer horsepower, Integer year, String gearbox, String category, Integer price) {
        this.brand = brand;
        this.model = model;
        this.horsepower = horsepower;
        this.year = year;
        this.gearbox = gearbox;
        this.category = category;
        this.price = price;
    }
}

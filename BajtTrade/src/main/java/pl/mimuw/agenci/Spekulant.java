package pl.mimuw.agenci;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import pl.mimuw.atrybuty.strategia.Strategia;

@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@Data
public class Spekulant extends Agent {
    private Strategia kariera;

    public double ileDiamentow() {
        return zasoby.getDiamenty();
    }
}

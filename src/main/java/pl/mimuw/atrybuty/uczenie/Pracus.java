package pl.mimuw.atrybuty.uczenie;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Gielda;

@EqualsAndHashCode(callSuper = true)
@Data
public class Pracus extends Uczenie {

    @Override
    public boolean czyDzisPracuje(Robotnik robotnik, Gielda gielda) {
        return true;
    }
}

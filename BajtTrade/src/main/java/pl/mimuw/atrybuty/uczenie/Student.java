package pl.mimuw.atrybuty.uczenie;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;

@EqualsAndHashCode(callSuper = true)
@Data
public class Student extends Uczenie {
    private int zapas;
    private int okres;

    @Override
    public boolean czyDzisPracuje(Robotnik robotnik, Gielda gielda) {
        return robotnik.getZasoby().getDiamenty() < 100 * zapas * gielda.dajSredniaCenZOkresu(okres, Ceny::getJedzenie);
    }
}

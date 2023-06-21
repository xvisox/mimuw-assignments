package pl.mimuw.atrybuty.uczenie;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Gielda;

@EqualsAndHashCode(callSuper = true)
@Data
public class Okresowy extends Uczenie {
    private int okresowosc_nauki;

    @Override
    public boolean czyDzisPracuje(Robotnik robotnik, Gielda gielda) {
        return gielda.getLiczbaDni() % okresowosc_nauki != 0;
    }
}

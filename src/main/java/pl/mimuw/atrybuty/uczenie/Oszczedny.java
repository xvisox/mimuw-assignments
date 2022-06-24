package pl.mimuw.atrybuty.uczenie;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Gielda;

@EqualsAndHashCode(callSuper = true)
@Data
public class Oszczedny extends Uczenie {
    private int limit_diamentow;

    @Override
    public boolean czyDzisPracuje(Robotnik robotnik, Gielda gielda) {
        return limit_diamentow <= robotnik.getZasoby().getDiamenty();
    }
}

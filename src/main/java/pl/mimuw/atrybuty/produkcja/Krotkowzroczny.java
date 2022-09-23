package pl.mimuw.atrybuty.produkcja;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.utility.UtilityMath;

@EqualsAndHashCode(callSuper = true)
@Data
public class Krotkowzroczny extends Produkcja {

    @Override
    public TypZasoby coDzisProdukuje(Robotnik robotnik, Gielda gielda) {
        Ceny cenyPoprzedniegoDnia = gielda.getDziennik().get(gielda.getLiczbaDni() - 1).getCeny_srednie();
        double cenaNarzedzia = cenyPoprzedniegoDnia.getNarzedzia();
        double cenaUbrania = cenyPoprzedniegoDnia.getUbrania();
        double cenaJedzenie = cenyPoprzedniegoDnia.getJedzenie();
        double cenaProgramy = cenyPoprzedniegoDnia.getProgramy();
        double maxCena = UtilityMath.max(cenaNarzedzia, cenaUbrania, cenaJedzenie, cenaProgramy);
        return zwrocNajlepszyProdukt(maxCena, cenaJedzenie, cenaNarzedzia, cenaUbrania, cenaProgramy);
    }
}

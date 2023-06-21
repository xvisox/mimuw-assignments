package pl.mimuw.atrybuty.produkcja;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.utility.UtilityMath;

import java.util.function.Function;

@EqualsAndHashCode(callSuper = true)
@Data
public class Perspektywiczny extends Produkcja {
    private int historia_perspektywy;

    // Zwraca różnice cen między dzisiaj a kiedyś.
    private double dajRoznice(TypZasoby typ, Ceny cenyKiedys, Ceny cenyWczoraj) {
        Function<Ceny, Double> getterCeny = Ceny.dajGetter(typ);
        assert getterCeny != null;
        return Math.abs(getterCeny.apply(cenyKiedys) - getterCeny.apply(cenyWczoraj));
    }

    @Override
    public TypZasoby coDzisProdukuje(Robotnik robotnik, Gielda gielda) {
        int dzienPorownywany = Math.max(gielda.getLiczbaDni() - historia_perspektywy, 0);
        Ceny cenyKiedys = gielda.getDziennik().get(dzienPorownywany).getCeny_srednie();
        Ceny cenyWczoraj = gielda.getDziennik().get(gielda.getLiczbaDni() - 1).getCeny_srednie();
        double roznicaJedzenie = dajRoznice(TypZasoby.JEDZENIE, cenyKiedys, cenyWczoraj);
        double roznicaUbrania = dajRoznice(TypZasoby.UBRANIA, cenyKiedys, cenyWczoraj);
        double roznicaProgramy = dajRoznice(TypZasoby.PROGRAMY, cenyKiedys, cenyWczoraj);
        double roznicaNarzedzia = dajRoznice(TypZasoby.NARZEDZIA, cenyKiedys, cenyWczoraj);
        double maxRoznica = UtilityMath.max(roznicaJedzenie, roznicaNarzedzia, roznicaUbrania, roznicaProgramy);
        return zwrocNajlepszyProdukt(maxRoznica, roznicaJedzenie, roznicaNarzedzia, roznicaUbrania, roznicaProgramy);
    }
}

package pl.mimuw.atrybuty.produkcja;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.AtrybutZasobow;
import pl.mimuw.atrybuty.zasoby.Produktywnosc;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.utility.UtilityMath;

import java.util.function.Function;

import static pl.mimuw.atrybuty.kariera.Kariera.dajPremieZaPoziom;
import static pl.mimuw.atrybuty.kariera.Kariera.dopasujKariereDoProduktu;

@EqualsAndHashCode(callSuper = true)
@Data
public class Chciwy extends Produkcja {

    // Zwraca ile zarobi robotnik po stworzeniu danego produktu.
    private double dajZysk(TypZasoby typ, Ceny ceny, Produktywnosc produktywnosc, Robotnik robotnik) {
        Function<AtrybutZasobow, Integer> getterZasoby = Produktywnosc.dajGetter(typ);
        Function<Ceny, Double> getterCeny = Ceny.dajGetter(typ);
        assert (getterCeny != null && getterZasoby != null);
        int calkowitaPremia = robotnik.getPosiadanaPremia();
        if (dopasujKariereDoProduktu(typ).equals(robotnik.getKariera()))
            calkowitaPremia += dajPremieZaPoziom(robotnik.getPoziom());
        return getterCeny.apply(ceny) * (getterZasoby.apply(produktywnosc)) * (calkowitaPremia + 100) / 100;
    }

    @Override
    public TypZasoby coDzisProdukuje(Robotnik robotnik, Gielda gielda) {
        Ceny cenyPoprzedniegoDnia = gielda.getDziennik().get(gielda.getLiczbaDni() - 1).getCeny_srednie();
        Produktywnosc produktywnosc = robotnik.getProduktywnosc();
        double zyskNarzedzia = dajZysk(TypZasoby.NARZEDZIA, cenyPoprzedniegoDnia, produktywnosc, robotnik);
        double zyskProgramy = dajZysk(TypZasoby.PROGRAMY, cenyPoprzedniegoDnia, produktywnosc, robotnik);
        double zyskUbrania = dajZysk(TypZasoby.UBRANIA, cenyPoprzedniegoDnia, produktywnosc, robotnik);
        double zyskJedzenie = dajZysk(TypZasoby.JEDZENIE, cenyPoprzedniegoDnia, produktywnosc, robotnik);
        double maxZysk = UtilityMath.max(zyskNarzedzia, zyskProgramy, zyskUbrania, zyskJedzenie);
        return zwrocNajlepszyProdukt(maxZysk, zyskJedzenie, zyskNarzedzia, zyskUbrania, zyskProgramy);
    }
}

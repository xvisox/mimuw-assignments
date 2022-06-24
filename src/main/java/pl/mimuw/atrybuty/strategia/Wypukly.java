package pl.mimuw.atrybuty.strategia;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaSpekulanta;

import java.util.function.Function;

@ToString(exclude = {"DZIEN_WCZESNIEJ", "DWA_DNI_WCZESNIEJ", "TRZY_DNI_WCZESNIEJ"})
@EqualsAndHashCode(callSuper = true)
@Data
public class Wypukly extends Strategia {
    @JsonIgnore
    private int DZIEN_WCZESNIEJ = 0;
    @JsonIgnore
    private int DWA_DNI_WCZESNIEJ = 1;
    @JsonIgnore
    private int TRZY_DNI_WCZESNIEJ = 2;

    // Funkcja sprawdzająca, czy ceny są funkcją wypukłą.
    private boolean czyWypukla(double y_1, double y_2, double y_3) {
        return y_2 <= (y_1 + y_3) / 2;
    }

    private void wystawOferte(Ceny[] ceny, Function<Ceny, Double> getter, Gielda gielda, TypZasoby typ, Spekulant spekulant) {
        double ceny1 = getter.apply(ceny[DZIEN_WCZESNIEJ]);
        double ceny2 = getter.apply(ceny[DWA_DNI_WCZESNIEJ]);
        double ceny3 = getter.apply(ceny[TRZY_DNI_WCZESNIEJ]);

        if (czyWypukla(ceny1, ceny2, ceny3)) {
            gielda.dodajOferteKupna(new OfertaSpekulanta(typ, ILOSC, spekulant, ceny1 * BUY, 0));
        } else {
            if (typ.equals(TypZasoby.JEDZENIE))
                gielda.dodajOferteSprzedazy(new OfertaSpekulanta(typ, ileJedzenia(spekulant), spekulant, ceny1 * SELL, 0));
            else
                wystawOfertySprzedazyProduktu(spekulant, typ, gielda, ceny1 * SELL);
        }
    }

    @Override
    public void wystawOferty(Spekulant spekulant, Gielda gielda) {
        if (gielda.getLiczbaDni() < 3) return;

        Ceny[] ceny = new Ceny[3];
        ceny[TRZY_DNI_WCZESNIEJ] = gielda.getDziennik().get(gielda.getLiczbaDni() - 3).getCeny_srednie();
        ceny[DWA_DNI_WCZESNIEJ] = gielda.getDziennik().get(gielda.getLiczbaDni() - 2).getCeny_srednie();
        ceny[DZIEN_WCZESNIEJ] = gielda.getDziennik().get(gielda.getLiczbaDni() - 1).getCeny_srednie();

        wystawOferte(ceny, Ceny::getJedzenie, gielda, TypZasoby.JEDZENIE, spekulant);
        wystawOferte(ceny, Ceny::getNarzedzia, gielda, TypZasoby.NARZEDZIA, spekulant);
        wystawOferte(ceny, Ceny::getUbrania, gielda, TypZasoby.UBRANIA, spekulant);
        wystawOferte(ceny, Ceny::getProgramy, gielda, TypZasoby.PROGRAMY, spekulant);
    }
}

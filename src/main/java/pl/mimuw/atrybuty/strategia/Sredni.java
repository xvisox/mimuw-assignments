package pl.mimuw.atrybuty.strategia;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.atrybuty.zasoby.Zasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaSpekulanta;

import java.util.function.Function;

@EqualsAndHashCode(callSuper = true)
@Data
public class Sredni extends Strategia {
    private int historia_spekulanta_sredniego;
    @JsonIgnore
    private int JEDZENIE = 0;
    @JsonIgnore
    private int UBRANIA = 1;
    @JsonIgnore
    private int PROGRAMY = 2;
    @JsonIgnore
    private int NARZEDZIA = 3;

    // Zwraca cenę kupna produktu.
    private double dajCeneKupna(Spekulant spekulant, double cenaSrednia, Function<Zasoby, Integer> getter) {
        return getter.apply(spekulant.getZasoby()) > 0 ? cenaSrednia * BUY : cenaSrednia * 0.95;
    }

    // Wystawia oferty kupna na wszystkie produkty.
    private void wystawOfertyKupna(Spekulant spekulant, Gielda gielda, double[] cenySrednie) {
        double cenaJedzenia = dajCeneKupna(spekulant, cenySrednie[JEDZENIE], Zasoby::getJedzenie);
        OfertaSpekulanta ofertaKupnaJedzenia = new OfertaSpekulanta(TypZasoby.JEDZENIE, ILOSC, spekulant, cenaJedzenia, 0);

        double cenaUbran = dajCeneKupna(spekulant, cenySrednie[UBRANIA], Zasoby::getUbrania);
        OfertaSpekulanta ofertaKupnaUbran = new OfertaSpekulanta(TypZasoby.UBRANIA, ILOSC, spekulant, cenaUbran, 0);

        double cenaProgramow = dajCeneKupna(spekulant, cenySrednie[PROGRAMY], Zasoby::getProgramy);
        OfertaSpekulanta ofertaKupnaProgramow = new OfertaSpekulanta(TypZasoby.PROGRAMY, ILOSC, spekulant, cenaProgramow, 0);

        double cenaNarzedzi = dajCeneKupna(spekulant, cenySrednie[NARZEDZIA], Zasoby::getNarzedzia);
        OfertaSpekulanta ofertaKupnaNarzedzi = new OfertaSpekulanta(TypZasoby.NARZEDZIA, ILOSC, spekulant, cenaNarzedzi, 0);

        gielda.dodajOferteKupna(ofertaKupnaJedzenia);
        gielda.dodajOferteKupna(ofertaKupnaNarzedzi);
        gielda.dodajOferteKupna(ofertaKupnaProgramow);
        gielda.dodajOferteKupna(ofertaKupnaUbran);
    }

    // Zwraca cenę sprzedaży produktu.
    private double dajCeneSprzedazy(double cenaSrednia) {
        return cenaSrednia * SELL;
    }

    // Wystawia oferty sprzedaży na wszystkie produkty.
    private void wystawOfertySprzedazy(Spekulant spekulant, Gielda gielda, double[] cenySrednie) {
        gielda.dodajOferteSprzedazy(
                new OfertaSpekulanta(TypZasoby.JEDZENIE, ileJedzenia(spekulant), spekulant, SELL * cenySrednie[JEDZENIE], 0));

        wystawOfertySprzedazyProduktu(spekulant, TypZasoby.UBRANIA, gielda, dajCeneSprzedazy(cenySrednie[UBRANIA]));
        wystawOfertySprzedazyProduktu(spekulant, TypZasoby.NARZEDZIA, gielda, dajCeneSprzedazy(cenySrednie[NARZEDZIA]));
        wystawOfertySprzedazyProduktu(spekulant, TypZasoby.PROGRAMY, gielda, dajCeneSprzedazy(cenySrednie[PROGRAMY]));
    }

    @Override
    public void wystawOferty(Spekulant spekulant, Gielda gielda) {
        double[] cenySrednie = new double[4];
        cenySrednie[JEDZENIE] = gielda.dajSredniaCenZOkresu(historia_spekulanta_sredniego, Ceny::getJedzenie);
        cenySrednie[NARZEDZIA] = gielda.dajSredniaCenZOkresu(historia_spekulanta_sredniego, Ceny::getNarzedzia);
        cenySrednie[PROGRAMY] = gielda.dajSredniaCenZOkresu(historia_spekulanta_sredniego, Ceny::getProgramy);
        cenySrednie[UBRANIA] = gielda.dajSredniaCenZOkresu(historia_spekulanta_sredniego, Ceny::getUbrania);

        wystawOfertyKupna(spekulant, gielda, cenySrednie);
        wystawOfertySprzedazy(spekulant, gielda, cenySrednie);
    }
}

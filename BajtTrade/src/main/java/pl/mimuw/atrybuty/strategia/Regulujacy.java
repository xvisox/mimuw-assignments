package pl.mimuw.atrybuty.strategia;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.AtrybutZasobow;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaSpekulanta;

import java.util.function.Function;

@EqualsAndHashCode(callSuper = true)
@Data
public class Regulujacy extends Strategia {

    // Funkcja zwracająca mnożnik ceny obliczony przez spekulanta regulującego.
    private double dajMnoznik(AtrybutZasobow iloscProduktowWczoraj, AtrybutZasobow iloscProduktowPrzedwczoraj, Function<AtrybutZasobow, Integer> getter) {
        double wynik = (double) getter.apply(iloscProduktowWczoraj) / (Math.max(getter.apply(iloscProduktowPrzedwczoraj), 1));
        wynik = Math.max(1, wynik);
        while (wynik > 10) wynik /= 10;
        while (wynik < 1) wynik *= 10;
        return wynik;
    }

    // Wystawia oferty sprzedaży na wszystkie produkty.
    private void wystawOfertySprzedazy(Spekulant spekulant, Gielda gielda, Ceny cenyPoWyliczeniu) {
        gielda.dodajOferteSprzedazy(
                new OfertaSpekulanta(TypZasoby.JEDZENIE, ileJedzenia(spekulant), spekulant, SELL * cenyPoWyliczeniu.getJedzenie(), 0));

        wystawOfertySprzedazyProduktu(spekulant, TypZasoby.UBRANIA, gielda, SELL * cenyPoWyliczeniu.getUbrania());
        wystawOfertySprzedazyProduktu(spekulant, TypZasoby.NARZEDZIA, gielda, SELL * cenyPoWyliczeniu.getNarzedzia());
        wystawOfertySprzedazyProduktu(spekulant, TypZasoby.PROGRAMY, gielda, SELL * cenyPoWyliczeniu.getProgramy());
    }

    // Wystawia oferty kupna na wszystkie produkty.
    private void wystawOfertyKupna(Spekulant spekulant, Gielda gielda, Ceny cenyPoWyliczeniu) {
        gielda.dodajOferteKupna(
                new OfertaSpekulanta(TypZasoby.JEDZENIE, ILOSC, spekulant, BUY * cenyPoWyliczeniu.getJedzenie(), 0));
        gielda.dodajOferteKupna(
                new OfertaSpekulanta(TypZasoby.NARZEDZIA, ILOSC, spekulant, BUY * cenyPoWyliczeniu.getNarzedzia(), 0));
        gielda.dodajOferteKupna(
                new OfertaSpekulanta(TypZasoby.PROGRAMY, ILOSC, spekulant, BUY * cenyPoWyliczeniu.getProgramy(), 0));
        gielda.dodajOferteKupna(
                new OfertaSpekulanta(TypZasoby.UBRANIA, ILOSC, spekulant, BUY * cenyPoWyliczeniu.getUbrania(), 0));
    }

    @Override
    public void wystawOferty(Spekulant spekulant, Gielda gielda) {
        // Spekulant regulujący nic nie robi w pierwszym dniu.
        if (gielda.getLiczbaDni() == 1) return;

        Ceny srednieCenyWczoraj = gielda.getDziennik().get(gielda.getLiczbaDni() - 1).getCeny_srednie();
        AtrybutZasobow iloscProduktowWczoraj = gielda.getDziennik().get(gielda.getLiczbaDni() - 1).getIleOfertSprzedazy();
        AtrybutZasobow iloscProduktowPrzedwczoraj = gielda.getDziennik().get(gielda.getLiczbaDni() - 2).getIleOfertSprzedazy();

        Ceny cenyPoWyliczeniu = new Ceny();
        cenyPoWyliczeniu.setJedzenie(srednieCenyWczoraj.getJedzenie() *
                dajMnoznik(iloscProduktowWczoraj, iloscProduktowPrzedwczoraj, AtrybutZasobow::getJedzenie));
        cenyPoWyliczeniu.setNarzedzia(srednieCenyWczoraj.getNarzedzia() *
                dajMnoznik(iloscProduktowWczoraj, iloscProduktowPrzedwczoraj, AtrybutZasobow::getNarzedzia));
        cenyPoWyliczeniu.setUbrania(srednieCenyWczoraj.getUbrania() *
                dajMnoznik(iloscProduktowWczoraj, iloscProduktowPrzedwczoraj, AtrybutZasobow::getUbrania));
        cenyPoWyliczeniu.setProgramy(srednieCenyWczoraj.getProgramy() *
                dajMnoznik(iloscProduktowWczoraj, iloscProduktowPrzedwczoraj, AtrybutZasobow::getProgramy));

        wystawOfertySprzedazy(spekulant, gielda, cenyPoWyliczeniu);
        wystawOfertyKupna(spekulant, gielda, cenyPoWyliczeniu);
    }
}

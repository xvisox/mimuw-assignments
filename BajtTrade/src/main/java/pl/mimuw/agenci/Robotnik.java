package pl.mimuw.agenci;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import pl.mimuw.atrybuty.kariera.TypKariera;
import pl.mimuw.atrybuty.kupowanie.Kupowanie;
import pl.mimuw.atrybuty.produkcja.Produkcja;
import pl.mimuw.atrybuty.uczenie.Uczenie;
import pl.mimuw.atrybuty.zasoby.*;
import pl.mimuw.atrybuty.zmiana.TypZmiany;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.gielda.Info;
import pl.mimuw.oferty.OfertaRobotnika;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Function;

import static pl.mimuw.atrybuty.kariera.Kariera.*;

@JsonIgnoreProperties(ignoreUnknown = true)
@ToString(callSuper = true, exclude = {"produktywnosc", "posiadanaPremia"})
@EqualsAndHashCode(callSuper = true)
@Data
public class Robotnik extends Agent {
    private int poziom;
    private TypZmiany zmiana;
    private TypKariera kariera;
    private Kupowanie kupowanie;
    private Produkcja produkcja;
    private Uczenie uczenie;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Produktywnosc produktywnosc;
    private int[] poziomyKariery; // Tablica przechowują poziomy rozwoju na danej ścieżce kariery.
    private int dniBezJedzenia; // Jeśli ten parametr wynosi -1 to robotnik jest martwy.
    @JsonIgnore
    private int posiadanaPremia; // Aktualnie naliczona premia od przedmiotów.
    @JsonIgnore
    private Wyprodukowane wyprodukowane; // Wyprodukowane przez robotnika w danej turze zasoby.

    public Robotnik() {
        poziomyKariery = new int[5];
        Arrays.fill(poziomyKariery, 1);
        posiadanaPremia = 0;
        dniBezJedzenia = 0;
        wyprodukowane = new Wyprodukowane();
    }

    // Robotnik się uczy.
    public void uczSie(Gielda gielda) {
        // Obsługa robotnika rewolucjonisty.
        if (zmiana.equals(TypZmiany.REWOLUCJONISTA) && (gielda.getLiczbaDni() + 1) % 7 == 0) {
            int okres = Math.max(1, id % 17);
            TypZasoby najczesciejSprzedawanyProdukt = gielda.dajNajczesciejSprzedawanyProduktZOkresu(okres);
            TypKariera nowaKariera = dopasujKariereDoProduktu(najczesciejSprzedawanyProdukt);
            // Jeśli wybrał taką samą karierę to zwiększenie poziomu.
            if (nowaKariera.equals(kariera)) {
                poziom++;
                poziomyKariery[dajIndeksKariery(kariera)]++;
            } else {
                // Jeśli wybrał nową karierę, to tylko zmieniamy jej nazwę i poziom.
                kariera = nowaKariera;
                poziom = poziomyKariery[dajIndeksKariery(nowaKariera)];
            }
            // Robotnik jest konserwatystą, więc tylko zwiększa poziom swoich kompetencji.
        } else {
            poziom++;
            poziomyKariery[dajIndeksKariery(kariera)]++;
        }
    }

    // Robotnik pracuje.
    public void pracuj(Gielda gielda) {
        // Wybór co produkuje robotnik i ile danego produktu trzeba stworzyć.
        TypZasoby produkt = coDzisProdukuje(gielda);
        int ileProduktu = ileTrzebaStworzyc(gielda);
        // Jeśli trzeba wyprodukować zerową ilość produktu, to nic nie robimy.
        if (ileProduktu != 0) {
            if (produkt.equals(TypZasoby.DIAMENTY)) {
                zasoby.setDiamenty(zasoby.getDiamenty() + ileProduktu);
                // Jedzenia nie trzeba tworzyć, bo ma zawsze taki sam poziom więc można je od razu wystawić na giełdę.
            } else if (produkt.equals(TypZasoby.JEDZENIE)) {
                OfertaRobotnika ofertaRobotnika = new OfertaRobotnika(produkt, ileProduktu, this, 0);
                gielda.dodajOferteSprzedazy(ofertaRobotnika);
            } else if (produkt.equals(TypZasoby.PROGRAMY)) {
                // Jeśli robotnik jest programistą, to ustawiamy poziom produkcji programu na poziom kariery.
                int poziomProgramu = kariera.equals(TypKariera.PROGRAMISTA) ? poziom : 1;
                OfertaRobotnika ofertaRobotnika = new OfertaRobotnika(produkt, ileProduktu, this, poziomProgramu);
                gielda.dodajOferteSprzedazy(ofertaRobotnika);
            } else {
                // Funkcja produkuje ubrania lub narzędzia.
                produkuj(ileProduktu);
                for (int i = 0; i < wyprodukowane.getWyprodukowaneProdukty().length; i++) {
                    if (wyprodukowane.getWyprodukowaneProdukty()[i] > 0) {
                        gielda.dodajOferteSprzedazy(new OfertaRobotnika(produkt, ileProduktu, this, i + 1));
                    }
                }
            }
        }
        // Robotnik wystawia ofertę kupna zgodnie ze swoją strategią.
        kupowanie.wystawOfertyKupna(this, gielda);
    }

    // Funkcja pomocnicza sprawdzająca, czy produkty zostały poprawnie stworzone.
    private void assertProdukcja(int ileProduktu) {
        int suma = 0;
        for (int j : wyprodukowane.getWyprodukowaneProdukty()) {
            suma += j;
        }
        assert suma == ileProduktu;
    }

    // Tworzy produkt i przekazuje go do obiektu wytworzone.
    private void produkuj(int ileProduktu) {
        int ile = ileProduktu;
        // Jeśli tworzymy narzędzia lub ubrania, to musimy znać poziomy programów robotnika.
        int najwiekszyPoziomProgramu = zasoby.dajNajwiekszyPoziom(TypZasoby.PROGRAMY);
        wyprodukowane.setWyprodukowaneProdukty(new int[najwiekszyPoziomProgramu]);
        ArrayList<Integer> poziomyProgramow = zasoby.getPoziomyZasobow().get(TypZasoby.PROGRAMY);
        int i = najwiekszyPoziomProgramu - 1;
        while (i >= 0 && ile > 0) {
            if (ile > poziomyProgramow.get(i)) {
                ile -= poziomyProgramow.get(i);
                wyprodukowane.getWyprodukowaneProdukty()[i] = poziomyProgramow.get(i);
                // Programy są od razu zużywane w trakcie produkcji.
                zwiekszZasoby(TypZasoby.PROGRAMY, -poziomyProgramow.get(i));
                poziomyProgramow.set(i, 0);
            }
            i--;
        }
        if (ile != 0) {
            wyprodukowane.getWyprodukowaneProdukty()[0] += ile;
        }
        zasoby.assertZasoby();
        assertProdukcja(ileProduktu);
    }

    // Funkcja zwraca, ile produktu ma stworzyć robotnik.
    private int ileTrzebaStworzyc(Gielda gielda) {
        TypZasoby produkt = coDzisProdukuje(gielda);
        int calkowitaPremia = posiadanaPremia;
        int wyprodukowanaIlosc;
        if (dopasujKariereDoProduktu(produkt).equals(kariera)) calkowitaPremia += dajPremieZaPoziom(poziom);

        if (!produkt.equals(TypZasoby.DIAMENTY)) {
            Function<AtrybutZasobow, Integer> getter = AtrybutZasobow.dajGetter(produkt);
            assert (getter != null);
            wyprodukowanaIlosc = getter.apply(produktywnosc) + (calkowitaPremia / 100) * getter.apply(produktywnosc);
        } else {
            wyprodukowanaIlosc = (int) (produktywnosc.getDiamenty() + (calkowitaPremia / 100) * produktywnosc.getDiamenty());
        }
        wyprodukowane.setIleWyprodukowano(Math.max(wyprodukowanaIlosc, 0));
        return wyprodukowane.getIleWyprodukowano();
    }

    public void ustawPremie(Info info) {
        // JEDZENIE
        switch (dniBezJedzenia) {
            case 0:
                break;
            case 1:
                zwiekszPremie(-100);
                break;
            case 2:
                zwiekszPremie(-300);
                break;
            default:
                // Robotnik umiera.
                zasoby.setDiamenty(0);
                dniBezJedzenia = -1;
        }
        // UBRANIA
        int poziom = 1;
        int sumaUbran = 0;
        for (int ile : zasoby.getPoziomyZasobow().get(TypZasoby.UBRANIA)) {
            sumaUbran += ile * Math.pow(poziom, 2);
            poziom++;
            if (sumaUbran >= 100) break;
        }
        if (sumaUbran < 100) zwiekszPremie(-info.getKara_za_brak_ubran());
        // NARZĘDZIA
        poziom = 1;
        for (int ile : zasoby.getPoziomyZasobow().get(TypZasoby.NARZEDZIA)) {
            zwiekszPremie(ile * poziom);
            poziom++;
        }
    }

    public void uzyjPrzedmioty() {
        if (!uczenie.czyPracuje()) {
            dniBezJedzenia = 0;
        } else {
            // JEDZENIE
            if (zasoby.getJedzenie() < 100) {
                zwiekszZasoby(TypZasoby.JEDZENIE, -zasoby.getJedzenie());
                dniBezJedzenia++;
            } else {
                zwiekszZasoby(TypZasoby.JEDZENIE, -100);
            }
            // UBRANIA
            int ileZuzyto = 0; // Ile ubrań razem użytych.
            int ubraniaDoZuzycia = 100;
            int poziom = 1;
            int ileUbran; // Ile ubrań konkretnego poziomu.
            ArrayList<Integer> poziomyUbran = zasoby.getPoziomyZasobow().get(TypZasoby.UBRANIA);
            for (int i = 0; i < poziomyUbran.size() && ubraniaDoZuzycia > 0; i++) {
                ileUbran = poziomyUbran.get(i);
                while (ileUbran > 0 && ubraniaDoZuzycia > 0) {
                    ileUbran--;
                    ileZuzyto++;
                    ubraniaDoZuzycia -= Math.pow(poziom, 2);
                }
                poziomyUbran.set(i, ileUbran);
                poziom++;
            }
            if (ubraniaDoZuzycia < 0) {
                assert (poziomyUbran.get(0) == 0);
                poziomyUbran.set(0, Math.abs(ubraniaDoZuzycia));
                ileZuzyto += ubraniaDoZuzycia;
            }
            zwiekszZasoby(TypZasoby.UBRANIA, -ileZuzyto);
            // NARZĘDZIA
            zwiekszZasoby(TypZasoby.NARZEDZIA, -zasoby.getNarzedzia());
            zasoby.getPoziomyZasobow().get(TypZasoby.NARZEDZIA).clear();
            // PROGRAMY (są zużywane w trakcie produkcji)
        }
        // Resetowanie premii związanych z przedmiotami.
        posiadanaPremia = 0;
        zasoby.assertZasoby();
    }

    public boolean czyDzisPracuje(Gielda gielda) {
        return uczenie.czyDzisPracuje(this, gielda);
    }

    public TypZasoby coDzisProdukuje(Gielda gielda) {
        return produkcja.coDzisProdukuje(this, gielda);
    }

    public void zwiekszLiczbeDiamentow(double ile) {
        zasoby.setDiamenty(zasoby.getDiamenty() + ile);
    }

    private void zwiekszPremie(int ile) {
        posiadanaPremia += ile;
    }

    public double ileDiamentow() {
        return zasoby.getDiamenty();
    }
}

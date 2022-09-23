package pl.mimuw;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.DzienGieldy;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.gielda.Info;
import pl.mimuw.oferty.OfertaRobotnika;
import pl.mimuw.oferty.OfertaSpekulanta;

import java.util.ArrayList;
import java.util.Comparator;

import static pl.mimuw.atrybuty.kariera.Kariera.dajIndeksKariery;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class BajtTrade {
    private Info info;
    private Robotnik[] robotnicy;
    private Spekulant[] spekulanci;
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Gielda gielda;

    public BajtTrade() {
        gielda = new Gielda();
    }


    // Inicjalizuje początkowe wartości symulacji.
    private void inicjalizujSymulacje() {
        for (Robotnik robotnik : robotnicy) {
            robotnik.getPoziomyKariery()[dajIndeksKariery(robotnik.getKariera())] += robotnik.getPoziom() - 1;
            robotnik.getZasoby().inicjalizujZasoby();
        }
        for (Spekulant spekulant : spekulanci) {
            spekulant.getZasoby().inicjalizujZasoby();
        }
    }

    // Funkcja wywołuje rozegranie dnia robotników.
    private void dzienRobotnikow() {
        for (Robotnik robotnik : robotnicy) {
            // To oznacza, że robotnik jest martwy.
            if (robotnik.getDniBezJedzenia() == -1) continue;
            if (robotnik.czyDzisPracuje(gielda)) {
                robotnik.getUczenie().setCzyPracuje(true);
                robotnik.pracuj(gielda);
            } else {
                robotnik.uczSie(gielda);
                robotnik.getUczenie().setCzyPracuje(false);
            }
        }
    }

    // Funkcja wywołuje rozegranie dnia spekulantów.
    private void dzienSpekulantow() {
        for (Spekulant spekulant : spekulanci) {
            spekulant.getKariera().wystawOferty(spekulant, gielda);
        }
    }

    private void sprzedajProdukt(OfertaRobotnika ofertaRobotnika, OfertaSpekulanta ofertaSpekulanta, boolean robotnikSprzedaje) {
        if (!ofertaRobotnika.getTyp().equals(ofertaSpekulanta.getTyp())) return;

        TypZasoby produkt = ofertaRobotnika.getTyp();
        int iloscDoSprzedania = robotnikSprzedaje ? ofertaRobotnika.getLiczba() : ofertaSpekulanta.getLiczba();
        int iloscDoKupienia = robotnikSprzedaje ? ofertaSpekulanta.getLiczba() : ofertaRobotnika.getLiczba();
        double cenaSpekulanta = ofertaSpekulanta.getCena();
        double liczbaDiamentowSpekulanta = ofertaSpekulanta.getSpekulant().getZasoby().getDiamenty();
        double liczbaDiamentowRobotnika = ofertaRobotnika.getRobotnik().getZasoby().getDiamenty();

        // Dopóki danego agenta stać by kupować od drugiego to, to robi.
        DzienGieldy dzienGieldy = gielda.getDziennik().get(gielda.getLiczbaDni() - 1);
        double liczbaDiamentowAgenta = robotnikSprzedaje ? liczbaDiamentowSpekulanta : liczbaDiamentowRobotnika;
        int mnoznik = robotnikSprzedaje ? 1 : -1;
        while (liczbaDiamentowAgenta > cenaSpekulanta && iloscDoKupienia > 0 && iloscDoSprzedania > 0) {
            liczbaDiamentowRobotnika += cenaSpekulanta * mnoznik;
            liczbaDiamentowSpekulanta -= cenaSpekulanta * mnoznik;
            liczbaDiamentowAgenta -= cenaSpekulanta;
            iloscDoKupienia--;
            iloscDoSprzedania--;
            if (robotnikSprzedaje) {
                // Zwiększanie licznika sprzedanych produktów.
                dzienGieldy.zwiekszLicznik(produkt, dzienGieldy.getIleOstatecznieSprzedanych(), 1);
                // Dodawanie ceny do sumy sprzedanych danego dnia produktów.
                dzienGieldy.zwiekszSume(ofertaSpekulanta);
            }
        }

        int ileSprzedano = robotnikSprzedaje ? ofertaRobotnika.getLiczba() : ofertaSpekulanta.getLiczba();
        // Jeśli cos zostało sprzedane.
        if (iloscDoSprzedania != ileSprzedano) {
            ileSprzedano -= iloscDoSprzedania;
            ofertaRobotnika.getRobotnik().getZasoby().setDiamenty(liczbaDiamentowRobotnika);
            ofertaRobotnika.setLiczba(iloscDoSprzedania);
            ofertaSpekulanta.getSpekulant().getZasoby().setDiamenty(liczbaDiamentowSpekulanta);
            ofertaSpekulanta.setLiczba(iloscDoKupienia);
            dzienGieldy.ustawMaxMin(produkt, cenaSpekulanta);

            if (robotnikSprzedaje)
                ofertaSpekulanta.getSpekulant().zwiekszZasoby(produkt, ileSprzedano);
            else
                ofertaRobotnika.getRobotnik().zwiekszZasoby(produkt, ileSprzedano);

            if (!produkt.equals(TypZasoby.JEDZENIE)) {
                ArrayList<Integer> poziomyProduktu;
                if (robotnikSprzedaje)
                    poziomyProduktu = ofertaSpekulanta.getSpekulant().getZasoby().getPoziomyZasobow().get(produkt);
                else
                    poziomyProduktu = ofertaRobotnika.getRobotnik().getZasoby().getPoziomyZasobow().get(produkt);

                int poziomProduktu = robotnikSprzedaje ? ofertaRobotnika.getPoziom() : ofertaSpekulanta.getPoziom();
                while (poziomyProduktu.size() < poziomProduktu) poziomyProduktu.add(0);
                assert (poziomyProduktu.get(poziomProduktu - 1) + ileSprzedano) > 0;
                poziomyProduktu.set(poziomProduktu - 1, poziomyProduktu.get(poziomProduktu - 1) + ileSprzedano);
            }
        }
    }

    // Zlicza ilość wystawionych ofert sprzedaży robotników.
    private void podliczOfertySprzedazy() {
        ArrayList<OfertaRobotnika> ofertySprzedazy;
        DzienGieldy dzienGieldy = gielda.getDziennik().get(gielda.getLiczbaDni() - 1);
        for (Robotnik robotnik : robotnicy) {
            ofertySprzedazy = gielda.getOfertySprzedazyRobotnikow().get(robotnik);
            if (ofertySprzedazy == null) continue;
            for (OfertaRobotnika ofertaRobotnika : ofertySprzedazy) {
                dzienGieldy.zwiekszLicznik(ofertaRobotnika.getTyp(), dzienGieldy.getIleOfertSprzedazy(), ofertaRobotnika.getLiczba());
            }
        }
    }

    private void dopasujOferty() {
        ArrayList<OfertaRobotnika> ofertySprzedazy;
        ArrayList<OfertaRobotnika> ofertyKupna;
        // Sortuje robotników według typu giełdy.
        gielda.sortujRobotnikow(info.getGielda(), robotnicy);
        // Robotnik chce sprzedawać spekulantom po najwyższych cenach.
        gielda.sortujOfertyKupnaCenamiMalejaco();
        // Robotnik chce kupować od spekulantów po najniższych cenach.
        gielda.sortujOfertySprzedazyCenamiRosnaco();
        for (Robotnik robotnik : robotnicy) {
            ofertySprzedazy = gielda.getOfertySprzedazyRobotnikow().get(robotnik);
            if (ofertySprzedazy != null) {
                ofertySprzedazy.sort(Comparator.comparing(OfertaRobotnika::getTyp));
                for (OfertaRobotnika ofertaRobotnika : ofertySprzedazy) {
                    for (OfertaSpekulanta ofertaSpekulanta : gielda.getOfertyKupnaSpekulantow()) {
                        sprzedajProdukt(ofertaRobotnika, ofertaSpekulanta, true);
                    }
                    // Usuwa puste oferty spekulantów.
                    gielda.getOfertyKupnaSpekulantow().removeIf(x -> x.getLiczba() == 0);
                }
            }
            ofertyKupna = gielda.getOfertyKupnaRobotnikow().get(robotnik);
            if (ofertyKupna != null) {
                ofertyKupna.sort(Comparator.comparing(OfertaRobotnika::getTyp));
                for (OfertaRobotnika ofertaRobotnika : ofertyKupna) {
                    for (OfertaSpekulanta ofertaSpekulanta : gielda.getOfertySprzedazySpekulantow()) {
                        sprzedajProdukt(ofertaRobotnika, ofertaSpekulanta, false);
                    }
                    // Usuwa puste oferty spekulantów.
                    gielda.getOfertySprzedazySpekulantow().removeIf(x -> x.getLiczba() == 0);
                }
            }
        }
    }

    // Zużywa pod koniec dnia przedmioty robotników.
    private void uzyjPrzedmiotyRobotnikow() {
        for (Robotnik robotnik : robotnicy) {
            if (robotnik.getDniBezJedzenia() == -1) continue;
            robotnik.uzyjPrzedmioty();
        }
    }

    // Zwiększa premie robotnikom za przedmioty.
    private void ustawPremieZaPrzedmioty() {
        for (Robotnik robotnik : robotnicy) {
            if (robotnik.getDniBezJedzenia() == -1) continue;
            robotnik.ustawPremie(info);
        }
    }

    public void wykonajSymulacje() {
        gielda.dodajDzienZero(info);
        inicjalizujSymulacje();

        for (int i = 0; i < info.getDlugosc(); i++) {
            ustawPremieZaPrzedmioty();
            dzienRobotnikow();
            dzienSpekulantow();
            gielda.dodajDzienGieldy(new DzienGieldy());
            podliczOfertySprzedazy();
            dopasujOferty();
            gielda.ustawCenySrednie();
            gielda.odkupWszystkieProdukty(robotnicy);
            gielda.usunStareOferty();
            uzyjPrzedmiotyRobotnikow();
        }
        gielda.sortujPoWygranych(robotnicy, spekulanci);
    }
}

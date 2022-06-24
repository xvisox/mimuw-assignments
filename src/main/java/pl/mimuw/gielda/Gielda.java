package pl.mimuw.gielda;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.atrybuty.zasoby.Zasoby;
import pl.mimuw.oferty.OfertaRobotnika;
import pl.mimuw.oferty.OfertaSpekulanta;
import pl.mimuw.utility.UtilityMath;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.function.Function;

import static java.util.Collections.reverseOrder;

@Data
@JsonIgnoreProperties(value = {"ofertyKupnaSpekulantow", "ofertySprzedazySpekulantow", "ofertyKupnaRobotnikow", "ofertySprzedazyRobotnikow"})
public class Gielda {
    private HashMap<Integer, DzienGieldy> dziennik;
    private ArrayList<OfertaSpekulanta> ofertyKupnaSpekulantow;
    private ArrayList<OfertaSpekulanta> ofertySprzedazySpekulantow;
    private HashMap<Robotnik, ArrayList<OfertaRobotnika>> ofertyKupnaRobotnikow;
    private HashMap<Robotnik, ArrayList<OfertaRobotnika>> ofertySprzedazyRobotnikow;
    private int liczbaDni; // liczba dni, które już się skończyły łącznie z dniem zero

    public Gielda() {
        this.dziennik = new HashMap<>();
        this.ofertySprzedazyRobotnikow = new HashMap<>();
        this.ofertySprzedazySpekulantow = new ArrayList<>();
        this.ofertyKupnaRobotnikow = new HashMap<>();
        this.ofertyKupnaSpekulantow = new ArrayList<>();
        this.liczbaDni = 0;
    }

    public void dodajDzienGieldy(DzienGieldy dzienGieldy) {
        dziennik.put(liczbaDni++, dzienGieldy);
    }

    // Zwraca średnią średnich cen z okresu danego w parametrze funkcji.
    public double dajSredniaCenZOkresu(int okres, Function<Ceny, Double> getter) {
        double sumaCen = getter.apply(dziennik.get(0).getCeny_srednie());
        int i = liczbaDni - 1;
        int j = okres;
        while (i > 0 && j > 0) {
            sumaCen += dziennik.get(i).getCeny_srednie().getJedzenie();
            i--;
            j--;
        }
        return j == 0 ? sumaCen / okres : sumaCen / liczbaDni;
    }

    // Zwraca najczęściej sprzedawany typ produktu z okresu danego w parametrze.
    public TypZasoby dajNajczesciejSprzedawanyProduktZOkresu(int okres) {
        if (liczbaDni == 1) return null;

        Zasoby zasobySuma = new Zasoby();
        int i = liczbaDni - 1;
        int j = okres;
        while (i > 0 && j > 0) {
            zasobySuma.zwiekszJedzenie(dziennik.get(i).getIleOfertSprzedazy().getJedzenie());
            zasobySuma.zwiekszUbrania(dziennik.get(i).getIleOfertSprzedazy().getUbrania());
            zasobySuma.zwiekszProgramy(dziennik.get(i).getIleOfertSprzedazy().getProgramy());
            zasobySuma.zwiekszNarzedzia(dziennik.get(i).getIleOfertSprzedazy().getNarzedzia());

            i--;
            j--;
        }
        int maxSuma = UtilityMath.max(zasobySuma.getJedzenie(), zasobySuma.getNarzedzia(), zasobySuma.getProgramy(), zasobySuma.getUbrania());
        if (maxSuma == zasobySuma.getJedzenie()) return TypZasoby.JEDZENIE;
        if (maxSuma == zasobySuma.getNarzedzia()) return TypZasoby.NARZEDZIA;
        if (maxSuma == zasobySuma.getProgramy()) return TypZasoby.PROGRAMY;
        if (maxSuma == zasobySuma.getUbrania()) return TypZasoby.UBRANIA;
        return null;
    }

    public void dodajOferteKupna(OfertaRobotnika ofertaRobotnika) {
        ofertyKupnaRobotnikow.putIfAbsent(ofertaRobotnika.getRobotnik(), new ArrayList<>());
        ofertyKupnaRobotnikow.get(ofertaRobotnika.getRobotnik()).add(ofertaRobotnika);
    }

    public void dodajOferteKupna(OfertaSpekulanta ofertaSpekulanta) {
        ofertyKupnaSpekulantow.add(ofertaSpekulanta);
    }

    public void dodajOferteSprzedazy(OfertaRobotnika ofertaRobotnika) {
        ofertySprzedazyRobotnikow.putIfAbsent(ofertaRobotnika.getRobotnik(), new ArrayList<>());
        ofertySprzedazyRobotnikow.get(ofertaRobotnika.getRobotnik()).add(ofertaRobotnika);
    }

    public void dodajOferteSprzedazy(OfertaSpekulanta ofertaSpekulanta) {
        ofertySprzedazySpekulantow.add(ofertaSpekulanta);
    }

    // Sortuje oferty spekulantów od najmniejszych cen.
    public void sortujOfertySprzedazyCenamiRosnaco() {
        Comparator<OfertaSpekulanta> poCenach = Comparator
                .comparing(OfertaSpekulanta::getTyp)
                .thenComparing(OfertaSpekulanta::getPoziom)
                .thenComparing(OfertaSpekulanta::getCena);
        ofertySprzedazySpekulantow.sort(poCenach);
    }

    // Sortuje oferty spekulantów od największych cen.
    public void sortujOfertyKupnaCenamiMalejaco() {
        Comparator<OfertaSpekulanta> poCenach = Comparator
                .comparing(OfertaSpekulanta::getTyp)
                .thenComparing(OfertaSpekulanta::getPoziom)
                .thenComparing(OfertaSpekulanta::getCena, reverseOrder());
        ofertyKupnaSpekulantow.sort(poCenach);
    }

    // Giełda odkupuje wszystkie produkty od robotników.
    public void odkupWszystkieProdukty(Robotnik[] robotnicy) {
        ArrayList<OfertaRobotnika> ofertySprzedazy;
        Function<Ceny, Double> getter;
        for (Robotnik robotnik : robotnicy) {
            ofertySprzedazy = ofertySprzedazyRobotnikow.get(robotnik);
            if (ofertySprzedazy == null) continue;
            for (OfertaRobotnika ofertaRobotnika : ofertySprzedazy) {
                getter = Ceny.dajGetter(ofertaRobotnika.getTyp());
                assert getter != null;
                ofertaRobotnika.zrealizuj(getter.apply(dziennik.get(liczbaDni - 2).getCeny_min()));
            }
        }
    }

    // Usuwa wszystkie pozostałe oferty.
    public void usunStareOferty() {
        ofertyKupnaSpekulantow.clear();
        ofertySprzedazySpekulantow.clear();
        ofertyKupnaRobotnikow.clear();
        ofertySprzedazyRobotnikow.clear();
    }

    // Ustawia średnie ceny w danym dniu.
    public void ustawCenySrednie() {
        dziennik.get(liczbaDni - 1).ustawCeny(dziennik.get(0));
    }

    // Sortuje robotników od tych z największą ilością diamentów.
    private void sortujKapitalistyczna(Robotnik[] robotnicy) {
        Comparator<Robotnik> kapitalistycznie = Comparator
                .comparing(Robotnik::ileDiamentow)
                .thenComparing(Robotnik::getId);
        Arrays.sort(robotnicy, kapitalistycznie.reversed());
    }

    // Sortuje robotników od tych z najmniejszą ilością diamentów.
    private void sortujSocjalistycznie(Robotnik[] robotnicy) {
        Comparator<Robotnik> kapitalistycznie = Comparator
                .comparing(Robotnik::ileDiamentow)
                .thenComparing(Robotnik::getId);
        Arrays.sort(robotnicy, kapitalistycznie);
    }

    public void sortujPoWygranych(Robotnik[] robotnicy, Spekulant[] spekulanci) {
        Comparator<Robotnik> wygraniRobotnicy = Comparator.comparing(Robotnik::ileDiamentow).reversed();
        Comparator<Spekulant> wygraniSpekulanci = Comparator.comparing(Spekulant::ileDiamentow).reversed();
        Arrays.sort(robotnicy, wygraniRobotnicy);
        Arrays.sort(spekulanci, wygraniSpekulanci);
    }

    // Sortuje robotników według typu giełdy.
    public void sortujRobotnikow(TypGieldy typGieldy, Robotnik[] robotnicy) {
        switch (typGieldy) {
            case KAPITALISTYCZNA:
                sortujKapitalistyczna(robotnicy);
                break;
            case SOCJALISTYCZNA:
                sortujSocjalistycznie(robotnicy);
                break;
            case ZROWNOWAZONA:
                if (liczbaDni % 2 == 1) {
                    sortujSocjalistycznie(robotnicy);
                } else {
                    sortujKapitalistyczna(robotnicy);
                }
                break;
        }
    }

    // Dodaje dzień zerowy do dziennika cen giełdy.
    public void dodajDzienZero(Info info) {
        DzienGieldy dzienZero = new DzienGieldy();
        dzienZero.setCeny_min(info.getCeny());
        dzienZero.setCeny_max(info.getCeny());
        dzienZero.setCeny_srednie(info.getCeny());
        dodajDzienGieldy(dzienZero);
    }
}

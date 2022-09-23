package pl.mimuw.gielda;

import lombok.Data;
import pl.mimuw.atrybuty.zasoby.AtrybutZasobow;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.oferty.OfertaSpekulanta;

import java.util.function.BiConsumer;
import java.util.function.Function;

@Data
public class DzienGieldy {
    private Ceny ceny_srednie;
    private Ceny ceny_min;
    private Ceny ceny_max;
    private AtrybutZasobow ileOfertSprzedazy;
    private AtrybutZasobow ileOstatecznieSprzedanych;

    public DzienGieldy() {
        this.ceny_srednie = new Ceny();
        this.ceny_min = new Ceny();
        this.ceny_min.ustawNaMax();
        this.ceny_max = new Ceny();
        this.ceny_max.ustawNaMin();
        this.ileOfertSprzedazy = new AtrybutZasobow();
        this.ileOstatecznieSprzedanych = new AtrybutZasobow();
    }

    // Ustawia na koniec dnia średnie ceny produktów i jeśli nie został
    // sprzedany żaden produkt to ustawia Max i Min cen na ceny z dnia zero.
    public void ustawCeny(DzienGieldy dzienZero) {
        if (ileOstatecznieSprzedanych.getNarzedzia() != 0) {
            ceny_srednie.setNarzedzia(ceny_srednie.getNarzedzia() / ileOstatecznieSprzedanych.getNarzedzia());
        } else {
            ceny_srednie.setNarzedzia(dzienZero.ceny_srednie.getNarzedzia());
            ceny_max.setNarzedzia(dzienZero.ceny_srednie.getNarzedzia());
            ceny_min.setNarzedzia(dzienZero.ceny_srednie.getNarzedzia());
        }

        if (ileOstatecznieSprzedanych.getJedzenie() != 0)
            ceny_srednie.setJedzenie(ceny_srednie.getJedzenie() / ileOstatecznieSprzedanych.getJedzenie());
        else {
            ceny_srednie.setJedzenie(dzienZero.ceny_srednie.getJedzenie());
            ceny_max.setJedzenie(dzienZero.ceny_srednie.getJedzenie());
            ceny_min.setJedzenie(dzienZero.ceny_srednie.getJedzenie());
        }

        if (ileOstatecznieSprzedanych.getProgramy() != 0)
            ceny_srednie.setProgramy(ceny_srednie.getProgramy() / ileOstatecznieSprzedanych.getProgramy());
        else {
            ceny_srednie.setProgramy(dzienZero.ceny_srednie.getProgramy());
            ceny_max.setProgramy(dzienZero.ceny_srednie.getProgramy());
            ceny_min.setProgramy(dzienZero.ceny_srednie.getProgramy());
        }

        if (ileOstatecznieSprzedanych.getUbrania() != 0)
            ceny_srednie.setUbrania(ceny_srednie.getUbrania() / ileOstatecznieSprzedanych.getUbrania());
        else {
            ceny_srednie.setUbrania(dzienZero.ceny_srednie.getUbrania());
            ceny_max.setUbrania(dzienZero.ceny_srednie.getUbrania());
            ceny_min.setUbrania(dzienZero.ceny_srednie.getUbrania());
        }
    }

    // Funkcja ustawiająca maksymalną i minimalną cenę.
    public void ustawMaxMin(TypZasoby typ, double cena) {
        BiConsumer<Ceny, Double> setterMin = ceny_min.dajSetter(typ);
        BiConsumer<Ceny, Double> setterMax = ceny_max.dajSetter(typ);
        Function<Ceny, Double> getter = Ceny.dajGetter(typ);
        assert (getter != null && setterMax != null && setterMin != null);

        setterMin.accept(ceny_min, Math.min(getter.apply(ceny_min), cena));
        setterMax.accept(ceny_max, Math.max(getter.apply(ceny_max), cena));
    }

    // Dodaje cenę produktu do sumy cen z danego dnia.
    public void zwiekszSume(OfertaSpekulanta ofertaSpekulanta) {
        double cenaSpekulanta = ofertaSpekulanta.getCena();
        BiConsumer<Ceny, Double> increment = ceny_srednie.dajIncrement(ofertaSpekulanta.getTyp());
        increment.accept(ceny_srednie, cenaSpekulanta);
    }

    // Zwiększa ilość sprzedanych produktów danego typu.
    public void zwiekszLicznik(TypZasoby typ, AtrybutZasobow zasoby, int ile) {
        BiConsumer<AtrybutZasobow, Integer> increment = zasoby.dajIncrement(typ);
        increment.accept(zasoby, ile);
    }
}


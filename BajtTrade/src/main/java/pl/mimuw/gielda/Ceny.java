package pl.mimuw.gielda;

import lombok.Data;
import pl.mimuw.atrybuty.zasoby.TypZasoby;

import java.util.function.BiConsumer;
import java.util.function.Function;

@Data
public class Ceny {
    private double programy;
    private double jedzenie;
    private double ubrania;
    private double narzedzia;

    // Zwraca getter ceny danego zasobu.
    public static Function<Ceny, Double> dajGetter(TypZasoby typ) {
        switch (typ) {
            case JEDZENIE:
                return Ceny::getJedzenie;
            case NARZEDZIA:
                return Ceny::getNarzedzia;
            case PROGRAMY:
                return Ceny::getProgramy;
            case UBRANIA:
                return Ceny::getUbrania;
        }
        return null;
    }

    // Zwraca setter ceny danego zasobu.
    public BiConsumer<Ceny, Double> dajSetter(TypZasoby typ) {
        switch (typ) {
            case PROGRAMY:
                return Ceny::setProgramy;
            case NARZEDZIA:
                return Ceny::setNarzedzia;
            case JEDZENIE:
                return Ceny::setJedzenie;
            case UBRANIA:
                return Ceny::setUbrania;
        }
        return null;
    }

    // Zwraca funkcje zwiększającą cenę danego produktu.
    public BiConsumer<Ceny, Double> dajIncrement(TypZasoby typ) {
        switch (typ) {
            case PROGRAMY:
                return Ceny::zwiekszCeneProgramy;
            case NARZEDZIA:
                return Ceny::zwiekszCeneNarzedzia;
            case JEDZENIE:
                return Ceny::zwiekszCeneJedzenia;
            case UBRANIA:
                return Ceny::zwiekszCeneUbrania;
        }
        return null;
    }

    public void zwiekszCeneNarzedzia(double cena) {
        narzedzia += cena;
    }

    public void zwiekszCeneUbrania(double cena) {
        ubrania += cena;
    }

    public void zwiekszCeneProgramy(double cena) {
        programy += cena;
    }

    public void zwiekszCeneJedzenia(double cena) {
        jedzenie += cena;
    }

    public void ustawNaMax() {
        programy = 999999;
        ubrania = 999999;
        jedzenie = 999999;
        narzedzia = 999999;
    }

    public void ustawNaMin() {
        programy = -1;
        ubrania = -1;
        jedzenie = -1;
        narzedzia = -1;
    }
}

package pl.mimuw.atrybuty.zasoby;

import lombok.Data;

import java.util.function.BiConsumer;
import java.util.function.Function;

@Data
public class AtrybutZasobow {
    protected double diamenty;
    protected int ubrania;
    protected int narzedzia;
    protected int jedzenie;
    protected int programy;

    // Zwraca getter danego zasobu.
    public static Function<AtrybutZasobow, Integer> dajGetter(TypZasoby typ) {
        switch (typ) {
            case PROGRAMY:
                return AtrybutZasobow::getProgramy;
            case NARZEDZIA:
                return AtrybutZasobow::getNarzedzia;
            case JEDZENIE:
                return AtrybutZasobow::getJedzenie;
            case UBRANIA:
                return AtrybutZasobow::getUbrania;
        }
        return null;
    }

    // Zwraca setter danego zasobu.
    public BiConsumer<AtrybutZasobow, Integer> dajSetter(TypZasoby typ) {
        switch (typ) {
            case PROGRAMY:
                return AtrybutZasobow::setProgramy;
            case NARZEDZIA:
                return AtrybutZasobow::setNarzedzia;
            case JEDZENIE:
                return AtrybutZasobow::setJedzenie;
            case UBRANIA:
                return AtrybutZasobow::setUbrania;
        }
        return null;
    }

    // Zwraca funkcje zwiększającą ilość danego produktu.
    public BiConsumer<AtrybutZasobow, Integer> dajIncrement(TypZasoby typ) {
        switch (typ) {
            case PROGRAMY:
                return AtrybutZasobow::zwiekszProgramy;
            case NARZEDZIA:
                return AtrybutZasobow::zwiekszNarzedzia;
            case JEDZENIE:
                return AtrybutZasobow::zwiekszJedzenie;
            case UBRANIA:
                return AtrybutZasobow::zwiekszUbrania;
        }
        return null;
    }

    public void zwiekszJedzenie(int ile) {
        jedzenie += ile;
    }

    public void zwiekszNarzedzia(int ile) {
        narzedzia += ile;
    }

    public void zwiekszUbrania(int ile) {
        ubrania += ile;
    }

    public void zwiekszProgramy(int ile) {
        programy += ile;
    }
}

package pl.mimuw.atrybuty.kariera;

import pl.mimuw.atrybuty.zasoby.TypZasoby;

import java.util.HashMap;
import java.util.Map;

public class Kariera {
    private static final Map<TypZasoby, TypKariera> dopasowanieKarieryDoProduktu = new HashMap<>();

    static {
        dopasowanieKarieryDoProduktu.put(TypZasoby.JEDZENIE, TypKariera.ROLNIK);
        dopasowanieKarieryDoProduktu.put(TypZasoby.UBRANIA, TypKariera.RZEMIESLNIK);
        dopasowanieKarieryDoProduktu.put(TypZasoby.NARZEDZIA, TypKariera.INZYNIER);
        dopasowanieKarieryDoProduktu.put(TypZasoby.DIAMENTY, TypKariera.GORNIK);
        dopasowanieKarieryDoProduktu.put(TypZasoby.PROGRAMY, TypKariera.PROGRAMISTA);
    }

    // Zwraca pasujący typ kariery do typu produktu.
    public static TypKariera dopasujKariereDoProduktu(TypZasoby produkt) {
        return dopasowanieKarieryDoProduktu.get(produkt);
    }

    // Zwraca indeks kariery w tablicy poziomów robotnika.
    public static int dajIndeksKariery(TypKariera nazwaKariery) {
        int result;
        switch (nazwaKariery) {
            case ROLNIK:
                result = 0;
                break;
            case GORNIK:
                result = 1;
                break;
            case RZEMIESLNIK:
                result = 2;
                break;
            case INZYNIER:
                result = 3;
                break;
            case PROGRAMISTA:
                result = 4;
                break;
            default:
                result = -1;
        }
        return result;
    }

    // Zwraca, jaką premie dostaje robotnik za dany poziom kariery.
    public static int dajPremieZaPoziom(int poziom) {
        int premia;
        switch (poziom) {
            case 0:
                premia = 0;
                break;
            case 1:
                premia = 50;
                break;
            case 2:
                premia = 150;
                break;
            case 3:
                premia = 300;
                break;
            default:
                premia = 300 + 25 * (poziom - 3);
                break;
        }
        return premia;
    }
}

package pl.mimuw.oferty;

import lombok.Data;
import pl.mimuw.atrybuty.zasoby.TypZasoby;

@Data
public class Oferta {
    private TypZasoby typ;
    private int liczba;
    private int poziom;

    // Oferty sprzedaży spekulantów i robotników mają poziomy.
    // Oferty kupna spekulantów i robotników nie mają poziomów (ozn. poziom = 0)
    public Oferta(TypZasoby typ, int liczba, int poziom) {
        assert (liczba != 0);
        this.typ = typ;
        this.liczba = liczba;
        this.poziom = poziom;
    }

    public Oferta() {
    }
}

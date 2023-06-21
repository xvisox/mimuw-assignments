package pl.mimuw.oferty;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;

@EqualsAndHashCode(callSuper = true)
@Data
public class OfertaRobotnika extends Oferta {
    private Robotnik robotnik;

    public OfertaRobotnika(TypZasoby typ, int liczba, Robotnik robotnik, int poziom) {
        super(typ, liczba, poziom);
        this.robotnik = robotnik;
    }

    public void zrealizuj(Double ile) {
        robotnik.zwiekszLiczbeDiamentow(ile);
    }
}

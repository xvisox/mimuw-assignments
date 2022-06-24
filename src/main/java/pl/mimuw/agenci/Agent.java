package pl.mimuw.agenci;

import lombok.Data;
import pl.mimuw.atrybuty.zasoby.AtrybutZasobow;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.atrybuty.zasoby.Zasoby;

import java.util.function.BiConsumer;
import java.util.function.Function;

@Data
public abstract class Agent {
    protected int id;
    protected Zasoby zasoby;

    // Zwiększa ilość zasobów wybranego typu.
    public void zwiekszZasoby(TypZasoby typ, int ile) {
        BiConsumer<AtrybutZasobow, Integer> setter = zasoby.dajSetter(typ);
        Function<AtrybutZasobow, Integer> getter = AtrybutZasobow.dajGetter(typ);
        assert (getter != null && setter != null);
        setter.accept(zasoby, getter.apply(zasoby) + ile);
    }
}

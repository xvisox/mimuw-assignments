package pl.mimuw.atrybuty.uczenie;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Gielda;

import static pl.mimuw.Main.random;

@EqualsAndHashCode(callSuper = true)
@Data
public class Rozkladowy extends Uczenie {

    @Override
    public boolean czyDzisPracuje(Robotnik robotnik, Gielda gielda) {
        // Parametr 'liczbaDni' mówi, ile dni już upłynęło na giełdzie dlatego aktualny dzień to liczbaDni + 1.
        return random.nextInt(gielda.getLiczbaDni() + 4) != 0;
    }
}

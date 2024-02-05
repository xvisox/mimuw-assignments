package pl.edu.mimuw.player.strategy

import pl.edu.mimuw.game.Dice
import pl.edu.mimuw.player.Player

class Thinker : GameplayStrategy {
    override fun shouldRollAgain(me: Player, opponent: Player, dice: Dice, numberOfRounds: Int): Boolean =
        (1 + dice.sides) / 2 > me.lastDiceRoll || me.lastDiceRoll < opponent.lastDiceRoll
}
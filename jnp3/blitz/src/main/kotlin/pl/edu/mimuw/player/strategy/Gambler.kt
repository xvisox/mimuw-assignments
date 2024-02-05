package pl.edu.mimuw.player.strategy

import pl.edu.mimuw.game.Dice
import pl.edu.mimuw.player.Player

class Gambler : GameplayStrategy {
    override fun shouldRollAgain(me: Player, opponent: Player, dice: Dice, numberOfRounds: Int): Boolean = true
}
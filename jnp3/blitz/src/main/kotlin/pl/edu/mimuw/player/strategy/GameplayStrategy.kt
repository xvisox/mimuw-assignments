package pl.edu.mimuw.player.strategy

import pl.edu.mimuw.game.Dice
import pl.edu.mimuw.player.Player

interface GameplayStrategy {
    fun shouldRollAgain(me: Player, opponent: Player, dice: Dice, numberOfRounds: Int): Boolean
}
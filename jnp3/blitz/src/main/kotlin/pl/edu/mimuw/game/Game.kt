package pl.edu.mimuw.game

import pl.edu.mimuw.player.Player

class Game(
    private val dice: Dice,
    private val numberOfRounds: Int,
    playerOne: Player,
    playerTwo: Player,
) {
    private val attacker: Player = if (playerOne.isAttacker()) playerOne else playerTwo
    private val defender: Player = if (playerOne.isAttacker()) playerTwo else playerOne

    init {
        assert(playerOne.isAttacker() != playerTwo.isAttacker())
    }

    fun play() {
        for (i in 1..numberOfRounds) playOneRound()

        if (attacker.currentScore > defender.currentScore)
            attacker.incrementWins()
        else if (attacker.currentScore < defender.currentScore)
            defender.incrementWins()
    }

    private fun playOneRound() {
        attacker.prepareForNewRound(); defender.prepareForNewRound()
        attacker.rollTheDice(dice); defender.rollTheDice(dice)

        if (attacker.shouldRollAgain(defender, dice, numberOfRounds))
            attacker.rollTheDice(dice)
        if (defender.shouldRollAgain(attacker, dice, numberOfRounds))
            defender.rollTheDice(dice)

        if (attacker.lastDiceRoll >= defender.lastDiceRoll)
            attacker.incrementCurrentScore()
        else
            defender.incrementCurrentScore()

    }
}
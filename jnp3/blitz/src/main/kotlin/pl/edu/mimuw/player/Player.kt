package pl.edu.mimuw.player

import pl.edu.mimuw.game.Dice
import pl.edu.mimuw.player.strategy.GameplayStrategy

class Player(private val strategy: GameplayStrategy, private var type: PlayerType) {
    var lastDiceRoll: Int = 0
        private set
    var currentScore: Int = 0
        private set
    var lifetimeWins: Int = 0
        private set
    var lifetimeWinsAsAttacker: Int = 0
        private set

    fun isAttacker(): Boolean = type == PlayerType.ATTACKER

    fun rollTheDice(dice: Dice) = dice.roll().also { lastDiceRoll = it }

    fun shouldRollAgain(opponent: Player, dice: Dice, numberOfRounds: Int): Boolean =
        strategy.shouldRollAgain(this, opponent, dice, numberOfRounds)

    fun incrementCurrentScore() = currentScore++

    fun incrementWins() {
        this.lifetimeWins++
        if (isAttacker()) this.lifetimeWinsAsAttacker++
        println("$type won!")
    }

    infix fun swapTypeWith(other: Player) {
        val temp = this.type
        this.type = other.type
        other.type = temp
    }

    fun prepareForNewRound() {
        currentScore = 0
        lastDiceRoll = 0
    }
}
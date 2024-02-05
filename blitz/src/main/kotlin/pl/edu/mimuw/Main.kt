package pl.edu.mimuw

import pl.edu.mimuw.game.Dice
import pl.edu.mimuw.game.Game
import pl.edu.mimuw.player.Player
import pl.edu.mimuw.player.PlayerType
import pl.edu.mimuw.player.strategy.Gambler
import pl.edu.mimuw.player.strategy.Thinker

const val LOWER_BOUND_DICE_SIDES = 2
const val UPPER_BOUND_DICE_SIDES = 99

const val LOWER_BOUND_GAME_ROUNDS = 5
const val UPPER_BOUND_GAME_ROUNDS = 99

const val NUMBER_OF_GAMES = 911
const val MASTER_DICE_SIDES = 2115

fun main() {
    val playerOne = Player(Gambler(), PlayerType.ATTACKER)
    val playerTwo = Player(Thinker(), PlayerType.DEFENDER)
    val masterDice = Dice(MASTER_DICE_SIDES)

    for (i in 1..NUMBER_OF_GAMES) {
        val diceSides = (LOWER_BOUND_DICE_SIDES..UPPER_BOUND_DICE_SIDES).random()
        val numberOfRounds = (LOWER_BOUND_GAME_ROUNDS..UPPER_BOUND_GAME_ROUNDS).random()

        if (masterDice.roll() % 2 == 0)
            playerOne swapTypeWith playerTwo

        println("======= GAME START =======")
        val formattedString = "Game params: dice sides = %2d, number of rounds = %2d, is player one attacker = %5s"
        println(String.format(formattedString, diceSides, numberOfRounds, playerOne.isAttacker()))
        Game(Dice(diceSides), numberOfRounds, playerOne, playerTwo).play()
    }

    println("------ SIMULATION RESULTS ------")
    val attackerWins = playerOne.lifetimeWinsAsAttacker + playerTwo.lifetimeWinsAsAttacker
    val defenderWins = playerOne.lifetimeWins + playerTwo.lifetimeWins - attackerWins
    val attackerFormattedPercentage = String.format("%.2f", (attackerWins.toDouble() / NUMBER_OF_GAMES) * 100)
    val defenderFormattedPercentage = String.format("%.2f", (defenderWins.toDouble() / NUMBER_OF_GAMES) * 100)
    println("Attacker role wins percentage: $attackerFormattedPercentage%")
    println("Defender role wins percentage: $defenderFormattedPercentage%")
    println("Games won by player one: ${playerOne.lifetimeWins}, and by player two: ${playerTwo.lifetimeWins}")
}

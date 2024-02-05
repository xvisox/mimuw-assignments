package pl.edu.mimuw.seega.io

import pl.edu.mimuw.seega.Constants
import pl.edu.mimuw.seega.Constants.Companion.MOVE
import pl.edu.mimuw.seega.Constants.Companion.DEPLOY
import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.MEDIUM_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.LARGE_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.DEPLOY_PATTERN
import pl.edu.mimuw.seega.domain.Direction

class InputReader {

    fun readBoardSize(): Int {
        return when (readln()) {
            "$SMALL_BOARD_SIZE" -> SMALL_BOARD_SIZE
            "$MEDIUM_BOARD_SIZE" -> MEDIUM_BOARD_SIZE
            "$LARGE_BOARD_SIZE" -> LARGE_BOARD_SIZE
            else -> throw Exception("Invalid board size.")
        }
    }

    fun readDeployCommand(): Pair<Char, Int> {
        val input = readln()
        val result = DEPLOY_PATTERN.matchEntire(input) ?: throw Exception("Invalid $DEPLOY command.")
        val field = result.value.split(' ')[1]
        return field[0] to field[1] - '0'
    }

    fun readMoveCommand(): Triple<Char, Int, Direction> {
        val input = readln()
        val result = Constants.MOVE_PATTERN.matchEntire(input) ?: throw Exception("Invalid $MOVE command.")
        val field = result.value.split(' ')[1]
        val direction = result.value.split(' ')[2]
        return Triple(field[0], field[1] - '0', Direction.valueOf(direction.uppercase()))
    }
}
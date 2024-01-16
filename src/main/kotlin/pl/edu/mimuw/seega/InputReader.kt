package pl.edu.mimuw.seega

import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.MEDIUM_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.LARGE_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.DEPLOY_PATTERN

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
        val result = DEPLOY_PATTERN.matchEntire(input) ?: throw Exception("Invalid deploy command.")
        val field = result.value.split(' ')[1]
        return field[0] to field[1] - '0'
    }
}
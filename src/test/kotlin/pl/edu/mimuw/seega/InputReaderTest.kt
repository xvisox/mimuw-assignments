package pl.edu.mimuw.seega

import com.github.stefanbirkner.systemlambda.SystemLambda.withTextFromSystemIn
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test
import pl.edu.mimuw.seega.Constants.Companion.DEPLOY
import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.MEDIUM_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.LARGE_BOARD_SIZE
import pl.edu.mimuw.seega.Constants.Companion.MOVE

class InputReaderTest {

    @Test
    fun `readBoardSize with valid input should return correct size`() {
        // given
        val inputReader = InputReader()

        // when & then
        withTextFromSystemIn("$SMALL_BOARD_SIZE", "$MEDIUM_BOARD_SIZE", "$LARGE_BOARD_SIZE").execute {
            assertEquals(SMALL_BOARD_SIZE, inputReader.readBoardSize())
            assertEquals(MEDIUM_BOARD_SIZE, inputReader.readBoardSize())
            assertEquals(LARGE_BOARD_SIZE, inputReader.readBoardSize())
        }
    }

    @Test
    fun `readBoardSize with invalid input should throw Exception`() {
        // given
        val inputReader = InputReader()

        // when & then
        withTextFromSystemIn("invalid", "3", "6", "11", "99").execute {
            repeat(5) { assertThrows<Exception> { inputReader.readBoardSize() } }
        }
    }

    @Test
    fun `readDeployCommand with valid input should return correct pair`() {
        // given
        val inputReader = InputReader()

        // when & then
        withTextFromSystemIn("$DEPLOY a1", "$DEPLOY b2", "$DEPLOY z9").execute {
            assertEquals('a' to 1, inputReader.readDeployCommand())
            assertEquals('b' to 2, inputReader.readDeployCommand())
            assertEquals('z' to 9, inputReader.readDeployCommand())
        }
    }

    @Test
    fun `readDeployCommand with invalid input should throw Exception`() {
        // given
        val inputReader = InputReader()

        // when & then
        withTextFromSystemIn(
            "invalid", "$DEPLOY a", "$DEPLOY 1",
            "$DEPLOY a0", "$DEPLOY a10", "$DEPLOY a11",
            "$DEPLOY a1 eee?", "$DEPLOY a1 a1", "$DEPLOY   a1"
        ).execute {
            repeat(9) { assertThrows<Exception> { inputReader.readDeployCommand() } }
        }
    }

    @Test
    fun `readMoveCommand with valid input should return correct Triple`() {
        // given
        val inputReader = InputReader()

        // when & then
        withTextFromSystemIn("$MOVE a1 up", "$MOVE b2 down", "$MOVE e5 left", "$MOVE z9 right").execute {
            assertEquals(Triple('a', 1, Direction.UP), inputReader.readMoveCommand())
            assertEquals(Triple('b', 2, Direction.DOWN), inputReader.readMoveCommand())
            assertEquals(Triple('e', 5, Direction.LEFT), inputReader.readMoveCommand())
            assertEquals(Triple('z', 9, Direction.RIGHT), inputReader.readMoveCommand())
        }
    }

    @Test
    fun `readMoveCommand with invalid input should throw Exception`() {
        // given
        val inputReader = InputReader()

        // when & then
        withTextFromSystemIn(
            "invalid", "$MOVE a", "$MOVE 1",
            "$MOVE a0", "$MOVE a10", "$MOVE a11",
            "$MOVE a1 eee?", "$MOVE a1 a1", "$MOVE   a1",
            "$MOVE a1 up down", "$MOVE a1 2 up", "$MOVE a1 up down left"
        ).execute {
            repeat(12) { assertThrows<Exception> { inputReader.readMoveCommand() } }
        }
    }
}

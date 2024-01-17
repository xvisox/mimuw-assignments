package pl.edu.mimuw.seega

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test
import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.exceptions.FieldEmptinessException
import pl.edu.mimuw.seega.exceptions.FieldOutOfBoundsException
import pl.edu.mimuw.seega.exceptions.FieldPlayerMismatchException

class SeegaControllerTest {

    @Test
    fun `executeDeploy with valid input should place pawn on the board`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when
        seegaController.executeDeploy('a', 1)

        // then
        assertFalse(board.isFieldEmpty('a', 1))
    }

    @Test
    fun `executeDeploy with out of bounds input should throw FieldOutOfBoundsException`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when & then
        assertThrows<FieldOutOfBoundsException> { seegaController.executeDeploy('a' + SMALL_BOARD_SIZE, 1) }
        assertThrows<FieldOutOfBoundsException> { seegaController.executeDeploy('a', 1 + SMALL_BOARD_SIZE) }
    }

    @Test
    fun `executeDeploy on non-empty field should throw FieldEmptinessException`() {
        // given
        val board = Board(SMALL_BOARD_SIZE).also { it.placePawn('a', 1, Field.WHITE) }
        val seegaController = SeegaController(board)

        // when & then
        assertThrows<FieldEmptinessException> { seegaController.executeDeploy('a', 1) }
    }

    @Test
    fun `isPhaseOne should return true when pawns count is less than board size`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        for (i in 1..SMALL_BOARD_SIZE) {
            for (j in 1..<SMALL_BOARD_SIZE) {
                if (board.isMiddleField('a' + i - 1, j)) continue
                seegaController.executeDeploy('a' + i - 1, j)
            }
        }

        // when & then
        assertTrue(seegaController.isPhaseOne())
    }

    @Test
    fun `isPhaseOne should return false when pawns count equals board size`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        for (i in 1..SMALL_BOARD_SIZE) {
            for (j in 1..SMALL_BOARD_SIZE) {
                if (board.isMiddleField('a' + i - 1, j)) continue
                seegaController.executeDeploy('a' + i - 1, j)
            }
        }

        // when & then
        assertFalse(seegaController.isPhaseOne())
    }

    @Test
    fun `changeColor should toggle currentPlayerColor between white and black`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when & then
        seegaController.changeColor()
        assert(seegaController.currentPlayerColor == Field.BLACK)

        seegaController.changeColor()
        assert(seegaController.currentPlayerColor == Field.WHITE)
    }

    @Test
    fun `executeMove with valid input should move pawn and capture opponents`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        seegaController.executeDeploy('a', 1)
        seegaController.executeDeploy('b', 3).also { seegaController.changeColor() }
        seegaController.executeDeploy('a', 2).also { seegaController.changeColor() }

        // when
        val pawnsTaken = seegaController.executeMove('b', 3, Direction.LEFT)

        // then
        assertTrue(pawnsTaken)
        assertTrue(board.isFieldEmpty('b', 3))
        assertTrue(board.isFieldEmpty('a', 2))
        assertFalse(board.isFieldEmpty('a', 1))
        assertFalse(board.isFieldEmpty('a', 3))
    }

    @Test
    fun `executeMove with invalid input should throw FieldOutOfBoundsException for out of bounds`() {
        // given
        val board = Board(5)
        val seegaController = SeegaController(board)

        seegaController.executeDeploy('a', 1)
        seegaController.executeDeploy('e', 5)

        // when & then
        assertThrows<FieldOutOfBoundsException> { seegaController.executeMove('a', 1, Direction.LEFT) }
        assertThrows<FieldOutOfBoundsException> { seegaController.executeMove('a', 1, Direction.UP) }
        assertThrows<FieldOutOfBoundsException> { seegaController.executeMove('e', 5, Direction.RIGHT) }
        assertThrows<FieldOutOfBoundsException> { seegaController.executeMove('e', 5, Direction.DOWN) }
    }

    @Test
    fun `executeMove with invalid input should throw FieldEmptinessException for empty field`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when & then
        assertThrows<FieldEmptinessException> { seegaController.executeMove('a', 1, Direction.DOWN) }
    }

    @Test
    fun `executeMove with invalid input should throw FieldEmptinessException for non-empty destination`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        seegaController.executeDeploy('a', 1)
        seegaController.executeDeploy('a', 2)

        // when & then
        assertThrows<FieldEmptinessException> { seegaController.executeMove('a', 1, Direction.DOWN) }
    }

    @Test
    fun `executeMove with invalid input should throw FieldPlayerMismatchException for moving opponent's pawn`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        seegaController.executeDeploy('a', 1).also { seegaController.changeColor() }

        // when & then
        assertThrows<FieldPlayerMismatchException> { seegaController.executeMove('a', 1, Direction.DOWN) }
    }

    @Test
    fun `proceedToNextPhase should remove special pawn from the center of the board`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when
        seegaController.proceedToNextPhase()

        // then
        assertTrue(board.isFieldEmpty('c', 3))
    }

    @Test
    fun `isPhaseTwo should return true when white and black pawns are still on the board`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        seegaController.executeDeploy('a', 1).also { seegaController.changeColor() }
        seegaController.executeDeploy('a', 2)

        // when
        val result = seegaController.isPhaseTwo()

        // then
        assertTrue(result)
    }

    @Test
    fun `isPhaseTwo should return false when either white or black pawns are eliminated`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        seegaController.executeDeploy('a', 1)
        seegaController.executeDeploy('b', 3).also { seegaController.changeColor() }
        seegaController.executeDeploy('a', 2).also { seegaController.changeColor() }
        assertTrue(seegaController.isPhaseTwo())

        // when
        seegaController.executeMove('b', 3, Direction.LEFT)
        val result = seegaController.isPhaseTwo()

        // then
        assertFalse(result)
    }
}
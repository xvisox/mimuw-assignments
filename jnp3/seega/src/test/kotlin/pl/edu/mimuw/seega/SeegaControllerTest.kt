package pl.edu.mimuw.seega

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test
import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.domain.Board
import pl.edu.mimuw.seega.domain.Direction
import pl.edu.mimuw.seega.domain.PawnColor
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
        seegaController.also {
            assertThrows<FieldOutOfBoundsException> { it.executeDeploy('a' + SMALL_BOARD_SIZE, 1) }
            assertThrows<FieldOutOfBoundsException> { it.executeDeploy('a', 1 + SMALL_BOARD_SIZE) }
        }
    }

    @Test
    fun `executeDeploy on non-empty field should throw FieldEmptinessException`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also { it.executeDeploy('a', 1) }

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
    fun `endPlayerTurn should toggle currentPlayerColor between white and black`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when & then
        seegaController.also {
            it.endPlayerTurn()
            assert(it.currentPlayerColor == PawnColor.BLACK)
            it.endPlayerTurn()
            assert(it.currentPlayerColor == PawnColor.WHITE)
        }
    }

    @Test
    fun `executeMove with valid input should move pawn and capture opponents`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.executeDeploy('b', 3)
            it.endPlayerTurn()
            it.executeDeploy('a', 2)
            it.endPlayerTurn()
        }

        // when
        val pawnsTaken = seegaController.executeMove('b', 3, Direction.LEFT)

        // then
        assertTrue(pawnsTaken.isNotEmpty())
        board.also {
            assertTrue(it.isFieldEmpty('b', 3))
            assertTrue(it.isFieldEmpty('a', 2))

            assertFalse(it.isFieldEmpty('a', 1))
            assertFalse(it.isFieldEmpty('a', 3))
        }
    }

    @Test
    fun `executeMove with invalid input should throw FieldOutOfBoundsException for out of bounds`() {
        // given
        val board = Board(5)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.executeDeploy('e', 5)
        }

        // when & then
        seegaController.also {
            assertThrows<FieldOutOfBoundsException> { it.executeMove('a', 1, Direction.LEFT) }
            assertThrows<FieldOutOfBoundsException> { it.executeMove('a', 1, Direction.UP) }
            assertThrows<FieldOutOfBoundsException> { it.executeMove('e', 5, Direction.RIGHT) }
            assertThrows<FieldOutOfBoundsException> { it.executeMove('e', 5, Direction.DOWN) }
        }
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
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.executeDeploy('a', 2)
        }

        // when & then
        assertThrows<FieldEmptinessException> { seegaController.executeMove('a', 1, Direction.DOWN) }
    }

    @Test
    fun `executeMove with invalid input should throw FieldPlayerMismatchException for moving opponent's pawn`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.endPlayerTurn()
        }

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
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.endPlayerTurn()
            it.executeDeploy('a', 2)
        }

        // when
        val result = seegaController.isPhaseTwo()

        // then
        assertTrue(result)
    }

    @Test
    fun `isPhaseTwo should return false when either white or black pawns are eliminated`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.executeDeploy('b', 3)
            it.endPlayerTurn()
            it.executeDeploy('a', 2)
            it.endPlayerTurn()
            assertTrue(it.isPhaseTwo())
        }

        // when
        seegaController.executeMove('b', 3, Direction.LEFT)
        val result = seegaController.isPhaseTwo()

        // then
        assertFalse(result)
    }

    @Test
    fun `executeMove should increase movesWithoutTaking when no pawns are taken`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also { it.executeDeploy('a', 1) }

        // when
        seegaController.also {
            it.executeMove('a', 1, Direction.DOWN)
            it.executeMove('a', 2, Direction.DOWN)
            it.executeMove('a', 3, Direction.DOWN)
        }

        // then
        assertEquals(3, seegaController.movesWithoutTaking)
    }

    @Test
    fun `executeMove should reset movesWithoutTaking when pawns are taken`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('a', 1)
            it.executeDeploy('b', 3)
            it.endPlayerTurn()
            it.executeDeploy('a', 2)
            it.endPlayerTurn()
        }

        // when
        seegaController.executeMove('b', 3, Direction.LEFT)

        // then
        assertEquals(0, seegaController.movesWithoutTaking)
    }

    @Test
    fun `isPhaseTwo should return false when movesWithoutTaking reaches 20`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('e', 5)
            it.endPlayerTurn()
            it.executeDeploy('a', 1)
        }

        repeat(10) {
            seegaController.executeMove('a', 1, Direction.RIGHT)
            seegaController.executeMove('b', 1, Direction.LEFT)
        }

        // when
        val result = seegaController.isPhaseTwo()

        // then
        assertFalse(result)
        assertEquals(20, seegaController.movesWithoutTaking)
    }

    @Test
    fun `isPhaseTwo should return true when movesWithoutTaking is less than 20`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('e', 5)
            it.endPlayerTurn()
            it.executeDeploy('a', 1)
        }

        repeat(9) {
            seegaController.executeMove('a', 1, Direction.RIGHT)
            seegaController.executeMove('b', 1, Direction.LEFT)
        }

        // when
        val result = seegaController.isPhaseTwo()

        // then
        assertTrue(result)
    }

    @Test
    fun `validMoveExistsForCurrentPlayer should return true when a valid move exists`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('b', 1)
            it.executeDeploy('a', 2)
            it.executeDeploy('b', 3)
            it.endPlayerTurn()
            it.executeDeploy('b', 2)
        }

        // when
        val result = seegaController.validMoveExistsForCurrentPlayer()

        // then
        assertTrue(result)
    }

    @Test
    fun `validMoveExistsForCurrentPlayer should return false when no valid move exists`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board).also {
            it.executeDeploy('b', 1)
            it.executeDeploy('a', 2)
            it.executeDeploy('c', 2)
            it.executeDeploy('b', 3)
            it.endPlayerTurn()
            it.executeDeploy('b', 2)
        }

        // when
        val result = seegaController.validMoveExistsForCurrentPlayer()

        // then
        assertFalse(result)
    }

    @Test
    fun `validMoveExistsForCurrentPlayer should return false when the board is empty`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when
        val result = seegaController.validMoveExistsForCurrentPlayer()

        // then
        assertFalse(result)
    }
}
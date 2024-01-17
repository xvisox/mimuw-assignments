package pl.edu.mimuw.seega

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test
import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE

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
    fun `executeDeploy with out of bounds input should throw Exception`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when & then
        assertThrows<Exception> { seegaController.executeDeploy('a' + SMALL_BOARD_SIZE, 1) }
    }

    @Test
    fun `executeDeploy on non-empty field should throw Exception`() {
        // given
        val board = Board(SMALL_BOARD_SIZE).also { it.placePawn('a', 1, Field.WHITE) }
        val seegaController = SeegaController(board)

        // when & then
        assertThrows<Exception> { seegaController.executeDeploy('a', 1) }
    }

    @Test
    fun `isPhaseOne should return true when pawns count is less than board size`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // executeDeploy() would throw an exception because
        // the field in the middle isn't empty
        for (i in 1..SMALL_BOARD_SIZE) {
            for (j in 1..<SMALL_BOARD_SIZE) {
                board.placePawn('a' + i - 1, j, Field.WHITE)
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
                board.placePawn('a' + i - 1, j, Field.WHITE)
            }
        }

        // when & then
        assertFalse(seegaController.isPhaseOne())
    }

    @Test
    fun `changeColor should toggle currentColor between white and black`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val seegaController = SeegaController(board)

        // when & then
        seegaController.changeColor()
        assert(seegaController.currentPlayerColor == Field.BLACK)

        seegaController.changeColor()
        assert(seegaController.currentPlayerColor == Field.WHITE)
    }

}
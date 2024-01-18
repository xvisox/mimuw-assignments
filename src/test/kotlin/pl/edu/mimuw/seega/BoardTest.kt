package pl.edu.mimuw.seega

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import pl.edu.mimuw.seega.Constants.Companion.SMALL_BOARD_SIZE
import pl.edu.mimuw.seega.domain.Board
import pl.edu.mimuw.seega.domain.Direction
import pl.edu.mimuw.seega.domain.PawnColor

class BoardTest {

    @Test
    fun `placePawn should update the board and pawn count`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        val initialWhitePawns = board.whitePawns
        val initialBlackPawns = board.blackPawns

        // when
        board.placePawn('a', 1, PawnColor.WHITE)

        // then
        assertEquals(PawnColor.WHITE, board.getFieldColor('a', 1))
        assertEquals(initialBlackPawns, board.blackPawns)
        assertEquals(initialWhitePawns + 1, board.whitePawns)
    }

    @Test
    fun `removePawn should update the board and pawn count`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        board.placePawn('a', 1, PawnColor.BLACK)
        val initialWhitePawns = board.whitePawns
        val initialBlackPawns = board.blackPawns

        // when
        board.removePawn('a', 1)

        // then
        assertEquals(PawnColor.EMPTY, board.getFieldColor('a', 1))
        assertEquals(initialBlackPawns - 1, board.blackPawns)
        assertEquals(initialWhitePawns, board.whitePawns)
    }

    @Test
    fun `movePawnAndGetNewField should move the pawn and update the board`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        board.placePawn('a', 1, PawnColor.WHITE)
        val initialWhitePawns = board.whitePawns
        val initialBlackPawns = board.blackPawns

        // when
        val (newCol, newRow) = board.movePawnAndGetNewField('a', 1, Direction.DOWN)

        // then
        assertEquals(PawnColor.EMPTY, board.getFieldColor('a', 1))
        assertEquals(PawnColor.WHITE, board.getFieldColor(newCol, newRow))
        assertEquals(initialBlackPawns, board.blackPawns)
        assertEquals(initialWhitePawns, board.whitePawns)
    }

    @Test
    fun `takeOpponentsPawnsAndGetResult should remove opponents' pawns and return the list of taken fields`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        board.placePawn('a', 1, PawnColor.WHITE)
        board.placePawn('a', 2, PawnColor.BLACK)
        board.placePawn('a', 3, PawnColor.WHITE)

        // when
        val takenFields = board.takeOpponentsPawnsAndGetResult('a', 1)

        // then
        assertEquals(1, takenFields.size)
        assertEquals(PawnColor.EMPTY, board.getFieldColor('a', 2))
    }

    @Test
    fun `takeOpponentsPawnsAndGetResult should remove all opponents' pawns`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        board.placePawn('a', 3, PawnColor.WHITE)
        board.placePawn('b', 3, PawnColor.BLACK)

        board.placePawn('d', 3, PawnColor.BLACK)
        board.placePawn('e', 3, PawnColor.WHITE)

        board.placePawn('c', 1, PawnColor.WHITE)
        board.placePawn('c', 2, PawnColor.BLACK)
        board.placePawn('c', 3, PawnColor.WHITE)

        val initialWhitePawns = board.whitePawns
        val initialBlackPawns = board.blackPawns

        // when
        val takenFields = board.takeOpponentsPawnsAndGetResult('c', 3)

        // then
        assertEquals(3, takenFields.size)
        assertEquals(initialBlackPawns - 3, board.blackPawns)
        assertEquals(initialWhitePawns, board.whitePawns)
        takenFields.forEach { assertEquals(PawnColor.EMPTY, board.getFieldColor(it.first, it.second)) }
    }

    @Test
    fun `takeOpponentsPawnsAndGetResult should ignore opponents' pawn in the middle`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        board.placePawn('b', 3, PawnColor.WHITE)
        board.placePawn('c', 3, PawnColor.BLACK)
        board.placePawn('d', 3, PawnColor.WHITE)
        val initialWhitePawns = board.whitePawns
        val initialBlackPawns = board.blackPawns

        // when
        val takenFields = board.takeOpponentsPawnsAndGetResult('b', 3)

        // then
        assertEquals(0, takenFields.size)
        assertEquals(initialBlackPawns, board.blackPawns)
        assertEquals(initialWhitePawns, board.whitePawns)
    }

    @Test
    fun `isFieldEmpty should return true for an empty field`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)

        // then
        assertTrue(board.isFieldEmpty('a', 1))
    }

    @Test
    fun `isFieldInBounds should return true for a valid field`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)

        // then
        assertTrue(board.isFieldInBounds('a', 1))
    }

    @Test
    fun `isFieldInBounds should return false for an out-of-bounds field`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)

        // then
        assertFalse(board.isFieldInBounds('a', 6))
    }

    @Test
    fun `isMiddleField should return true for the center field`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)

        // then
        assertTrue(board.isMiddleField('c', 3))
    }

    @Test
    fun `getFieldColor should return the correct PawnColor`() {
        // given
        val board = Board(SMALL_BOARD_SIZE)
        board.placePawn('a', 1, PawnColor.BLACK)

        // then
        assertEquals(PawnColor.BLACK, board.getFieldColor('a', 1))
    }
}
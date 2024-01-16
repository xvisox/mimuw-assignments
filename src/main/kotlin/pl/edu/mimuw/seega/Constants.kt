package pl.edu.mimuw.seega

class Constants {
    companion object {
        val FIRST_ROW_INDENT = " ".repeat(5)
        val FIRST_ROW_SPACING = " ".repeat(3)
        val ROW_INDENT = " ".repeat(3)

        const val BLACK = 'B'
        const val WHITE = 'W'

        const val DEPLOY = "deploy"
        const val MOVE = "move"
        val DEPLOY_PATTERN = Regex("$DEPLOY [a-z][1-9]")
        val MOVE_PATTERN = Regex("$MOVE [a-z][1-9] [a-z]{2}")
    }
}
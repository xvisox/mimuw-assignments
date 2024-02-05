package pl.edu.mimuw.dsl.smd

class Constants private constructor() {
    companion object {
        const val MAIN_HEADER_TAG = "======"
        const val SECONDARY_HEADER_TAG = "------"
        const val HORIZONTAL_RULE_TAG = "---"
        const val NEWLINE = "\n"
        const val DOUBLE_NEWLINE = "\n\n"
        const val DOUBLE_SPACE = "  "
        const val EMPTY_STRING = ""
        const val CODE_BLOCK_TAG = "```"
        const val CODE_TAG = "`"
        const val BOLD_TAG = "**"
        const val ITALIC_TAG = "*"
        const val ITEM_TAG = "- "
        const val ITEM_TAG_WITH_NUMBER = ". "
    }
}

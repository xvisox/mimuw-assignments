package pl.edu.mimuw.dsl.smd

import pl.edu.mimuw.dsl.smd.Constants.Companion.BOLD_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.CODE_BLOCK_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.CODE_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.DOUBLE_NEWLINE
import pl.edu.mimuw.dsl.smd.Constants.Companion.DOUBLE_SPACE
import pl.edu.mimuw.dsl.smd.Constants.Companion.NEWLINE
import pl.edu.mimuw.dsl.smd.Constants.Companion.EMPTY_STRING
import pl.edu.mimuw.dsl.smd.Constants.Companion.HORIZONTAL_RULE_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.ITALIC_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.ITEM_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.ITEM_TAG_WITH_NUMBER
import pl.edu.mimuw.dsl.smd.Constants.Companion.MAIN_HEADER_TAG
import pl.edu.mimuw.dsl.smd.Constants.Companion.SECONDARY_HEADER_TAG

@DslMarker
annotation class SmdTagMaker

@SmdTagMaker
abstract class Tag(private val tagStart: String = EMPTY_STRING, private val tagEnd: String = EMPTY_STRING) : Element {
    val children = arrayListOf<Element>()

    protected fun <T : Element> initTag(tag: T, init: T.() -> Unit): T {
        tag.init()
        children.add(tag)
        return tag
    }

    override fun render(builder: StringBuilder) {
        builder.append(tagStart)
        children.forEach {
            it.render(builder)
        }
        builder.append(tagEnd)
    }

    override fun toString(): String {
        val builder = StringBuilder()
        render(builder)
        return builder.toString()
    }

    // Auxiliary tag for users to have more control over the output.
    fun nl(init: NewLine.() -> Unit) = initTag(NewLine(), init)
}

abstract class TagWithText(tagStart: String = EMPTY_STRING, tagEnd: String) : Tag(tagStart, tagEnd) {
    operator fun String.unaryPlus() {
        children.add(TextElement(this))
    }

    fun bold(init: Bold.() -> Unit) = initTag(Bold(), init)
    fun italic(init: Italic.() -> Unit) = initTag(Italic(), init)
    fun code(init: Code.() -> Unit) = initTag(Code(), init)
}

class SMD : Tag() {
    fun p(init: Paragraph.() -> Unit) = initTag(Paragraph(), init)
    fun h1(init: MainHeader.() -> Unit) = initTag(MainHeader(), init)
    fun h2(init: SecondaryHeader.() -> Unit) = initTag(SecondaryHeader(), init)
    fun hr(init: HorizontalRule.() -> Unit) = initTag(HorizontalRule(), init)
    fun item(init: Item.() -> Unit) = initTag(Item(ITEM_TAG), init)
    fun item(num: Int, init: Item.() -> Unit) = initTag(Item("$num${ITEM_TAG_WITH_NUMBER}"), init)
    fun codeBlock(init: CodeBlock.() -> Unit) = initTag(CodeBlock(), init)

    fun writeToFile(filePath: String) {
        val file = java.io.File(filePath)
        file.writeText(toString())
        print("File saved to $filePath")
    }
}

fun buildSMD(init: SMD.() -> Unit): SMD {
    val smd = SMD()
    smd.init()
    return smd
}

class MainHeader : TagWithText(tagEnd = "${NEWLINE}${MAIN_HEADER_TAG}${DOUBLE_NEWLINE}")

class SecondaryHeader : TagWithText(tagEnd = "${NEWLINE}${SECONDARY_HEADER_TAG}${DOUBLE_NEWLINE}")

class Paragraph : TagWithText(tagEnd = DOUBLE_NEWLINE) {
    fun br(init: BreakLine.() -> Unit) = initTag(BreakLine(), init)
}

class BreakLine : Tag(tagEnd = "${DOUBLE_SPACE}${NEWLINE}")

class NewLine : Tag(tagEnd = NEWLINE)

class HorizontalRule : Tag(tagEnd = "${HORIZONTAL_RULE_TAG}${NEWLINE}")

class Item(tagStart: String) : TagWithText(tagStart, tagEnd = NEWLINE)

class Italic : TagWithText(ITALIC_TAG, ITALIC_TAG)

class Bold : TagWithText(BOLD_TAG, BOLD_TAG)

class Code : TagWithText(CODE_TAG, CODE_TAG)

class CodeBlock : TagWithText("${CODE_BLOCK_TAG}${NEWLINE}", "${NEWLINE}${CODE_BLOCK_TAG}${NEWLINE}")
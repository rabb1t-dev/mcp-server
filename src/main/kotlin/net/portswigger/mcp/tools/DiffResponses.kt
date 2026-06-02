package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class ResponseDiff(
    val leftStatus: Int,
    val rightStatus: Int,
    val statusDelta: Int,
    val leftLength: Int,
    val rightLength: Int,
    val lengthDelta: Int,
    val similarity: Double,
    val addedLines: List<String>,
    val removedLines: List<String>,
    val firstDiffSnippets: List<String>
)

fun diffResponses(
    leftContent: String,
    rightContent: String,
    leftStatus: Int = -1,
    rightStatus: Int = -1,
    maxLines: Int = 10
): ResponseDiff {
    val leftLines = leftContent.lines()
    val rightLines = rightContent.lines()
    val leftSet = leftLines.toSet()
    val rightSet = rightLines.toSet()

    val added = rightLines.filter { it !in leftSet }.take(maxLines)
    val removed = leftLines.filter { it !in rightSet }.take(maxLines)

    val snippets = mutableListOf<String>()
    val minSize = minOf(leftLines.size, rightLines.size)
    for (i in 0 until minSize) {
        if (leftLines[i] != rightLines[i]) {
            snippets.add("- ${leftLines[i].take(120)}")
            snippets.add("+ ${rightLines[i].take(120)}")
            if (snippets.size >= maxLines * 2) break
        }
    }

    return ResponseDiff(
        leftStatus = leftStatus,
        rightStatus = rightStatus,
        statusDelta = rightStatus - leftStatus,
        leftLength = leftContent.length,
        rightLength = rightContent.length,
        lengthDelta = rightContent.length - leftContent.length,
        similarity = responseSimilarity(leftContent, rightContent),
        addedLines = added,
        removedLines = removed,
        firstDiffSnippets = snippets.take(maxLines * 2)
    )
}

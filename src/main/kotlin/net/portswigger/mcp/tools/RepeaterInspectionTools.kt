package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.McpConfig
import java.awt.Component
import java.awt.Container
import javax.swing.JLabel
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/**
 * The Montoya API only exposes a write-only [burp.api.montoya.repeater.Repeater.sendToRepeater] method - there is no
 * official way to enumerate or read back existing Repeater tabs. To support "read this Repeater tab by name", we
 * instead walk Burp's own Swing UI tree (the same approach [getActiveEditor] uses for the active message editor) to
 * find a tab whose title matches, then pull the raw text out of its request/response editors.
 *
 * This is inherently a best-effort UI-scraping approach and may break across Burp UI versions. It requires the tab
 * to actually exist (and have been rendered) in the running Burp instance.
 */
data class RepeaterTabContent(
    val tabTitle: String,
    val request: String?,
    val response: String?
)

fun Server.registerRepeaterInspectionTools(api: MontoyaApi, config: McpConfig) {
    mcpTool(
        "list_repeater_tabs",
        "Lists the names/titles of Repeater tabs that are currently open in Burp's UI. Use this to discover the " +
            "exact tab name to pass to get_repeater_tab."
    ) {
        val titles = runOnEdt { findRepeaterTabTitles(api) }

        if (titles.isEmpty()) {
            "No Repeater tabs were found. They must be open in Burp's UI to be discovered."
        } else {
            titles.joinToString("\n")
        }
    }

    mcpTool<GetRepeaterTab>(
        "Reads the request and response currently shown in a Repeater tab, identified by its tab name/title " +
            "(as displayed in the Repeater tab bar, e.g. 'MyTab1'). Matches an exact name first, falling back to a " +
            "case-insensitive match. Use list_repeater_tabs to see available tab names."
    ) {
        val result = runOnEdt { findRepeaterTabContent(api, tabName) }
            ?: return@mcpTool "No Repeater tab found with name '$tabName'. Use list_repeater_tabs to see available tab names."

        buildString {
            appendLine("Repeater tab: ${result.tabTitle}")
            appendLine()
            appendLine("--- Request ---")
            appendLine(result.request ?: "<Could not read request content>")
            appendLine()
            appendLine("--- Response ---")
            appendLine(result.response ?: "<No response, or could not read response content>")
        }
    }
}

@Serializable
data class GetRepeaterTab(val tabName: String)

internal fun findRepeaterTabContent(api: MontoyaApi, tabName: String): RepeaterTabContent? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val matches = findTabMatches(frame, tabName)
    val match = matches.firstOrNull { isMessageEditorTab(it.component) } ?: matches.firstOrNull() ?: return null

    val panes = findRequestResponsePanes(match.component)
    val request = panes?.first?.let { extractEditorText(it) }
    val response = panes?.second?.let { extractEditorText(it) }

    return RepeaterTabContent(match.title, request, response)
}

internal fun findRepeaterTabTitles(api: MontoyaApi): List<String> {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val titles = mutableListOf<String>()

    fun visit(component: Component) {
        if (component is JTabbedPane) {
            for (i in 0 until component.tabCount) {
                val content = component.getComponentAt(i)
                if (content != null && isMessageEditorTab(content)) {
                    titles += tabTitleAt(component, i)
                }
            }
        }
        if (component is Container) {
            component.components.forEach(::visit)
        }
    }

    visit(frame)
    return titles.distinct()
}

private data class TabMatch(val title: String, val component: Component)

private fun findTabMatches(root: Component, tabName: String): List<TabMatch> {
    val exact = mutableListOf<TabMatch>()
    val caseInsensitive = mutableListOf<TabMatch>()

    fun visit(component: Component) {
        if (component is JTabbedPane) {
            for (i in 0 until component.tabCount) {
                val title = tabTitleAt(component, i)
                val content = component.getComponentAt(i) ?: continue
                when {
                    title == tabName -> exact += TabMatch(title, content)
                    title.equals(tabName, ignoreCase = true) -> caseInsensitive += TabMatch(title, content)
                }
            }
        }
        if (component is Container) {
            component.components.forEach(::visit)
        }
    }

    visit(root)
    return exact.ifEmpty { caseInsensitive }
}

private fun tabTitleAt(pane: JTabbedPane, index: Int): String {
    val title = pane.getTitleAt(index)
    if (title.isNotBlank()) return title

    return pane.getTabComponentAt(index)?.findFirst<JLabel>()?.text ?: ""
}

/** Repeater/Intruder message tabs have a distinctive request|response (or top/bottom) split with editable text on both sides. */
private fun isMessageEditorTab(component: Component): Boolean {
    val panes = findRequestResponsePanes(component) ?: return false
    return panes.first.findFirst<JTextArea>() != null && panes.second.findFirst<JTextArea>() != null
}

private fun findRequestResponsePanes(tabComponent: Component): Pair<Component, Component>? {
    val split = tabComponent.findFirst<JSplitPane>() ?: return null
    val first = split.leftComponent ?: split.topComponent ?: return null
    val second = split.rightComponent ?: split.bottomComponent ?: return null
    return first to second
}

private fun extractEditorText(component: Component): String? {
    val areas = component.findAll<JTextArea>()
    if (areas.isEmpty()) return null

    return (areas.firstOrNull { it.isShowing } ?: areas.first()).text
}

private fun <T : Component> findFirstDescendant(root: Component, type: Class<T>): T? {
    if (type.isInstance(root)) {
        @Suppress("UNCHECKED_CAST")
        return root as T
    }
    if (root is Container) {
        for (child in root.components) {
            findFirstDescendant(child, type)?.let { return it }
        }
    }
    return null
}

private fun <T : Component> findAllDescendants(root: Component, type: Class<T>, results: MutableList<T> = mutableListOf()): List<T> {
    if (type.isInstance(root)) {
        @Suppress("UNCHECKED_CAST")
        results += root as T
    }
    if (root is Container) {
        for (child in root.components) {
            findAllDescendants(child, type, results)
        }
    }
    return results
}

private inline fun <reified T : Component> Component.findFirst(): T? = findFirstDescendant(this, T::class.java)

private inline fun <reified T : Component> Component.findAll(): List<T> = findAllDescendants(this, T::class.java)

internal fun <T> runOnEdt(block: () -> T): T {
    if (SwingUtilities.isEventDispatchThread()) return block()

    var result: T? = null
    var error: Throwable? = null

    SwingUtilities.invokeAndWait {
        try {
            result = block()
        } catch (e: Throwable) {
            error = e
        }
    }

    error?.let { throw it }

    @Suppress("UNCHECKED_CAST")
    return result as T
}

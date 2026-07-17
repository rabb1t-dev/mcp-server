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
 * to actually exist in the running Burp instance. Two Burp UI quirks make this trickier than a plain tab search:
 *
 * - Only the *currently selected* Repeater tab has its request/response editor fully realized; other tabs are
 *   lightweight stubs until clicked. We work around this for [get_repeater_tab][findRepeaterTabContent] by
 *   temporarily selecting the target tab (restoring the previous selection afterward).
 * - A structural "does this contain a request/response split" check is too promiscuous to use for *enumerating*
 *   tabs: it also matches Burp's own top-level "Repeater" suite tab (which obviously contains such a split
 *   somewhere deep inside) and small single-tab "Request"/"Response" wrapper panes used purely for styling inside
 *   a single editor. [findRepeaterTabTitles] instead identifies the tab *strip* itself, then returns every tab it
 *   has, rather than filtering tab-by-tab.
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

    mcpTool<CloseRepeaterTab>(
        "Closes an existing Repeater tab identified by its name/title, discarding any unsaved draft content in " +
            "it. Matches an exact name first, falling back to case-insensitive. If multiple tabs share that name, " +
            "only the first match is closed unless closeAll is set. Use list_repeater_tabs to see available tab names."
    ) {
        val result = runOnEdt { closeRepeaterTabs(api, tabName, closeAll) }

        when {
            result.totalMatches == 0 ->
                "No Repeater tab found with name '$tabName'. Use list_repeater_tabs to see available tab names."

            result.closedCount == result.totalMatches ->
                "Closed ${result.closedCount} Repeater tab(s) named '$tabName'."

            else ->
                "Closed 1 of ${result.totalMatches} Repeater tabs named '$tabName'. Pass closeAll=true to close the rest."
        }
    }
}

@Serializable
data class GetRepeaterTab(val tabName: String)

@Serializable
data class CloseRepeaterTab(val tabName: String, val closeAll: Boolean = false)

/**
 * Reads a tab's content by title. If the matching tab isn't currently selected (and so hasn't been realized by
 * Burp yet), it's temporarily selected to force Burp to materialize its editors, then the previous selection is
 * restored so the user's Burp UI ends up looking the way it did before this call.
 */
internal fun findRepeaterTabContent(api: MontoyaApi, tabName: String): RepeaterTabContent? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val matches = findTabMatches(frame, tabName)
    if (matches.isEmpty()) return null

    val match = matches.firstOrNull { it.component?.let(::isMessageEditorTab) == true } ?: matches.first()

    val previousIndex = match.pane.selectedIndex
    val needsActivation = previousIndex != match.index
    if (needsActivation) match.pane.selectedIndex = match.index

    try {
        val panes = match.component?.let { findRequestResponsePanes(it) }
        val request = panes?.first?.let { extractEditorText(it) }
        val response = panes?.second?.let { extractEditorText(it) }
        return RepeaterTabContent(match.title, request, response)
    } finally {
        if (needsActivation) match.pane.selectedIndex = previousIndex
    }
}

data class CloseRepeaterTabsResult(val closedCount: Int, val totalMatches: Int)

/**
 * Closes one or more tabs matching the given title. By default only the first match is closed (mirroring the
 * exact-then-case-insensitive preference used elsewhere); pass closeAll to close every matching tab. When closing
 * multiple tabs that live on the same JTabbedPane, they're removed from the highest index down so that removing one
 * doesn't shift the indices of the others still pending removal.
 */
internal fun closeRepeaterTabs(api: MontoyaApi, tabName: String, closeAll: Boolean): CloseRepeaterTabsResult {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val matches = findTabMatches(frame, tabName)
    if (matches.isEmpty()) return CloseRepeaterTabsResult(closedCount = 0, totalMatches = 0)

    val toClose = if (closeAll) matches else matches.take(1)

    toClose.groupBy { it.pane }.forEach { (pane, matchesInPane) ->
        matchesInPane.sortedByDescending { it.index }.forEach { pane.removeTabAt(it.index) }
    }

    return CloseRepeaterTabsResult(closedCount = toClose.size, totalMatches = matches.size)
}

/**
 * Enumerates every tab on the Repeater tab strip, regardless of whether each one is currently realized. Title
 * strings are stored on the JTabbedPane model itself and are available for every tab immediately - unlike the
 * request/response editors, which are only built for the currently selected tab - so unlike content extraction,
 * enumeration doesn't need to activate anything.
 */
internal fun findRepeaterTabTitles(api: MontoyaApi): List<String> {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val strip = findRepeaterTabStrip(frame) ?: return emptyList()

    return (0 until strip.tabCount).map { tabTitleAt(strip, it) }
}

private val KNOWN_BURP_TOOL_TAB_TITLES = setOf(
    "Target", "Proxy", "Intruder", "Repeater", "Sequencer", "Decoder", "Comparer", "Logger", "Organizer", "Extensions"
)

/**
 * Finds Burp's own main tool-switcher tab strip (Dashboard/Target/Proxy/.../Repeater/...) if the current UI uses a
 * classic JTabbedPane for it, and returns the content of its "Repeater" tab. Scoping subsequent searches to this
 * panel avoids confusing Burp's fixed set of ~10 main tool tabs (or small nested sub-tabs inside a single editor,
 * e.g. a single-tab "Request"/"Response" wrapper used purely for styling) with the actual user-named Repeater tab
 * strip. Returns null if this signature isn't found (e.g. a future Burp UI that doesn't use a JTabbedPane for the
 * main tool switcher), in which case callers fall back to searching the whole frame.
 */
private fun findRepeaterToolPanel(root: Component): Component? {
    if (root is JTabbedPane) {
        val titles = (0 until root.tabCount).map { tabTitleAt(root, it) }
        val knownToolTabCount = titles.count { it in KNOWN_BURP_TOOL_TAB_TITLES }
        val repeaterIndex = titles.indexOf("Repeater")

        if (knownToolTabCount >= 2 && repeaterIndex >= 0) {
            return root.getComponentAt(repeaterIndex)
        }
    }

    if (root is Container) {
        for (child in root.components) {
            findRepeaterToolPanel(child)?.let { return it }
        }
    }

    return null
}

/**
 * Finds the JTabbedPane that holds the individual, user-named Repeater tabs. Scoped to the Repeater tool's own
 * panel when it can be located (see [findRepeaterToolPanel]); within that scope, picks the JTabbedPane with the
 * most tabs among those with at least one tab that looks like a message editor - a user with several dozen
 * Repeater tabs open will dwarf any small nested "Request"/"Response" wrapper panes (usually just one tab each).
 */
private fun findRepeaterTabStrip(root: Component): JTabbedPane? {
    val scopedRoot = findRepeaterToolPanel(root) ?: root
    return collectQualifyingTabbedPanes(scopedRoot).maxByOrNull { it.tabCount }
}

private fun collectQualifyingTabbedPanes(root: Component): List<JTabbedPane> {
    val results = mutableListOf<JTabbedPane>()

    if (root is JTabbedPane) {
        val hasMessageEditorTab = (0 until root.tabCount).any { i ->
            root.getComponentAt(i)?.let(::isMessageEditorTab) == true
        }
        if (hasMessageEditorTab) results += root
    }

    if (root is Container) {
        root.components.forEach { results += collectQualifyingTabbedPanes(it) }
    }

    return results
}

private data class TabMatch(val title: String, val pane: JTabbedPane, val index: Int) {
    val component: Component? get() = pane.getComponentAt(index)
}

private fun findTabMatches(root: Component, tabName: String): List<TabMatch> {
    val exact = mutableListOf<TabMatch>()
    val caseInsensitive = mutableListOf<TabMatch>()

    fun visit(component: Component) {
        if (component is JTabbedPane) {
            for (i in 0 until component.tabCount) {
                val title = tabTitleAt(component, i)
                when {
                    title == tabName -> exact += TabMatch(title, component, i)
                    title.equals(tabName, ignoreCase = true) -> caseInsensitive += TabMatch(title, component, i)
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

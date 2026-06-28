package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.LoggerCaptureStore
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.ItemEvent
import javax.swing.*
import javax.swing.Box.createVerticalStrut

class LoggerCapturePanel(
    private val config: McpConfig,
    private val loggerStore: LoggerCaptureStore,
    private val isProfessional: Boolean,
) : JPanel() {

    private val maxEntriesField = JTextField(8)

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        updateColors()
        alignmentX = LEFT_ALIGNMENT
        buildPanel()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        add(Design.createSectionLabel("Logger Capture"))
        add(createVerticalStrut(Design.Spacing.SM))
        add(
            JLabel(
                "Captures cross-tool HTTP traffic (Scanner, Repeater, Intruder, Extensions, Proxy) for MCP queries. " +
                    "Forward-only from extension load."
            ).apply {
                font = Design.Typography.labelMedium
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = LEFT_ALIGNMENT
            }
        )
        add(createVerticalStrut(Design.Spacing.MD))

        add(createCheckBox("Enable Logger capture", config.loggerCaptureEnabled) {
            config.loggerCaptureEnabled = it
        })
        add(createVerticalStrut(Design.Spacing.SM))

        add(createCheckBox("Capture extension traffic", config.loggerCaptureExtensions) {
            config.loggerCaptureExtensions = it
        })
        add(createVerticalStrut(Design.Spacing.MD))

        add(createMaxEntriesPanel())
        add(createVerticalStrut(Design.Spacing.MD))

        val persistenceCheckBox = createCheckBox(
            "Persist Logger capture to project file (Burp Pro, saved project)",
            config.loggerPersistenceEnabled
        ) {
            config.loggerPersistenceEnabled = it
        }.apply {
            isEnabled = isProfessional
            toolTipText = if (isProfessional) {
                "Opt-in: stores captured traffic in the project file (bodies truncated to 50KB)."
            } else {
                "Requires Burp Suite Professional with a saved project."
            }
        }
        add(persistenceCheckBox)
        add(createVerticalStrut(Design.Spacing.MD))

        add(createClearPanel())
    }

    private fun createMaxEntriesPanel(): JPanel {
        maxEntriesField.text = config.loggerMaxEntries.toString()
        maxEntriesField.preferredSize = Dimension(120, 32)
        maxEntriesField.font = Design.Typography.bodyLarge

        maxEntriesField.addActionListener { applyMaxEntries() }
        maxEntriesField.addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) {
                applyMaxEntries()
            }
        })

        val panel = JPanel(GridBagLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
        }

        val gbc = GridBagConstraints().apply {
            insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, Design.Spacing.MD)
            anchor = GridBagConstraints.WEST
        }

        gbc.gridx = 0
        gbc.gridy = 0
        panel.add(
            JLabel("Max entries in memory:").apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurface
            },
            gbc
        )

        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        panel.add(maxEntriesField, gbc)

        return panel
    }

    private fun applyMaxEntries() {
        val parsed = maxEntriesField.text.trim().toIntOrNull()?.coerceIn(100, 50_000) ?: config.loggerMaxEntries
        config.loggerMaxEntries = parsed
        maxEntriesField.text = parsed.toString()
    }

    private fun createClearPanel(): JPanel {
        val clearButton = JButton("Clear Logger capture").apply {
            font = Design.Typography.bodyLarge
            addActionListener {
                val confirmed = JOptionPane.showConfirmDialog(
                    this@LoggerCapturePanel,
                    "Clear all captured Logger traffic from memory and persisted storage?",
                    "Clear Logger Capture",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
                if (confirmed == JOptionPane.OK_OPTION) {
                    loggerStore.clear()
                }
            }
        }

        return JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(clearButton)
        }
    }

    private fun createCheckBox(
        text: String,
        initialValue: Boolean,
        onChange: (Boolean) -> Unit,
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }
}

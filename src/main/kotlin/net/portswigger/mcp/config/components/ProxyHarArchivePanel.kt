package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.ProxyHarArchiveStore
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.*
import javax.swing.Box.createVerticalStrut
import javax.swing.filechooser.FileSystemView

class ProxyHarArchivePanel(
    private val config: McpConfig,
    private val archiveStore: ProxyHarArchiveStore,
) : JPanel() {

    private val engagementDirField = JTextField(40)
    private val batchSizeField = JTextField(8)

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
        add(Design.createSectionLabel("Proxy HAR Archive"))
        add(createVerticalStrut(Design.Spacing.SM))
        add(
            JLabel(
                "Auto-exports proxy history batches to {engagement directory}/proxy-archives/. " +
                    "Burp's proxy history is never deleted by this extension — export first, then clear manually in Burp when you want."
            ).apply {
                font = Design.Typography.labelMedium
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = LEFT_ALIGNMENT
            }
        )
        add(createVerticalStrut(Design.Spacing.MD))

        engagementDirField.text = config.engagementDirectory
        batchSizeField.text = config.proxyHarBatchSize.toString()

        add(createEngagementDirectoryPanel())
        add(createVerticalStrut(Design.Spacing.SM))
        add(createBatchSizePanel())
        add(createVerticalStrut(Design.Spacing.MD))

        add(
            createCheckBox("Enable automatic proxy HAR export", config.proxyHarAutoExportEnabled) {
                config.proxyHarAutoExportEnabled = it
            }
        )
        add(createVerticalStrut(Design.Spacing.MD))

        add(
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                alignmentX = LEFT_ALIGNMENT
                add(Design.createOutlinedButton("Export all now").apply {
                    addActionListener {
                        val (_, message) = archiveStore.exportAllToHar()
                        JOptionPane.showMessageDialog(this@ProxyHarArchivePanel, message)
                    }
                })
                add(Box.createHorizontalStrut(Design.Spacing.SM))
                add(Design.createTextButton("Reset export cursor").apply {
                    addActionListener {
                        archiveStore.resetExportCursor()
                        JOptionPane.showMessageDialog(
                            this@ProxyHarArchivePanel,
                            "Auto-export cursor reset. Next batch starts from current history index 0."
                        )
                    }
                })
            }
        )
    }

    private fun createEngagementDirectoryPanel(): JPanel {
        val browseButton = Design.createOutlinedButton("Browse").apply {
            addActionListener {
                val chooser = JFileChooser(FileSystemView.getFileSystemView().homeDirectory).apply {
                    fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
                    dialogTitle = "Select engagement directory"
                }
                if (chooser.showOpenDialog(this@ProxyHarArchivePanel) == JFileChooser.APPROVE_OPTION) {
                    engagementDirField.text = chooser.selectedFile.absolutePath
                    applyEngagementDirectory()
                }
            }
        }

        engagementDirField.font = Design.Typography.bodyLarge
        engagementDirField.addActionListener { applyEngagementDirectory() }
        engagementDirField.addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) {
                applyEngagementDirectory()
            }
        })

        return JPanel(GridBagLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            val gbc = GridBagConstraints().apply {
                insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, Design.Spacing.MD)
                anchor = GridBagConstraints.WEST
            }

            gbc.gridx = 0
            gbc.gridy = 0
            add(JLabel("Engagement directory:").apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurface
            }, gbc)

            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.weightx = 1.0
            engagementDirField.preferredSize = Dimension(320, 32)
            add(engagementDirField, gbc)

            gbc.gridx = 2
            gbc.fill = GridBagConstraints.NONE
            gbc.weightx = 0.0
            add(browseButton, gbc)
        }
    }

    private fun createBatchSizePanel(): JPanel {
        batchSizeField.preferredSize = Dimension(120, 32)
        batchSizeField.font = Design.Typography.bodyLarge
        batchSizeField.addActionListener { applyBatchSize() }
        batchSizeField.addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) {
                applyBatchSize()
            }
        })

        return JPanel(GridBagLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            val gbc = GridBagConstraints().apply {
                insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, Design.Spacing.MD)
                anchor = GridBagConstraints.WEST
            }

            gbc.gridx = 0
            gbc.gridy = 0
            add(JLabel("Auto-export batch size:").apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurface
            }, gbc)

            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.weightx = 1.0
            add(batchSizeField, gbc)
        }
    }

    private fun applyEngagementDirectory() {
        config.engagementDirectory = engagementDirField.text.trim()
    }

    private fun applyBatchSize() {
        val parsed = batchSizeField.text.trim().toIntOrNull()?.coerceIn(10, 500) ?: config.proxyHarBatchSize
        config.proxyHarBatchSize = parsed
        batchSizeField.text = parsed.toString()
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
                onChange(event.stateChange == java.awt.event.ItemEvent.SELECTED)
            }
        }
    }
}

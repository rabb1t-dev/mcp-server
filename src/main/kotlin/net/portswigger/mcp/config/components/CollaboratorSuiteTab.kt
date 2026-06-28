package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.CollaboratorManager
import java.awt.BorderLayout
import java.awt.Dimension
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.Box.createVerticalStrut
import javax.swing.table.DefaultTableModel

class CollaboratorSuiteTab(
    private val manager: CollaboratorManager,
) : JPanel(BorderLayout()) {

    private val payloadModel = DefaultTableModel(arrayOf("Payload", "ID", "Created"), 0)
    private val interactionModel = DefaultTableModel(arrayOf("Type", "Client IP", "Time", "Summary"), 0)
    private val statusLabel = JLabel("Polling every 3s")

    private val refreshListener: () -> Unit = { refreshTables() }

    init {
        updateColors()
        buildUi()
        manager.addListener(refreshListener)
        refreshTables()
    }

    fun shutdown() {
        manager.removeListener(refreshListener)
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
    }

    private fun buildUi() {
        val header = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            border = BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, 0, Design.Spacing.MD)
            add(Design.createSectionLabel("MCP Collaborator"))
            add(createVerticalStrut(Design.Spacing.SM))
            add(
                JLabel(
                    "Payloads generated via MCP and live OOB interactions. " +
                        "This complements Burp's built-in Collaborator tab."
                ).apply {
                    font = Design.Typography.labelMedium
                    foreground = Design.Colors.onSurfaceVariant
                }
            )
            add(createVerticalStrut(Design.Spacing.SM))
            add(
                JPanel().apply {
                    layout = BoxLayout(this, BoxLayout.X_AXIS)
                    isOpaque = false
                    add(Design.createOutlinedButton("Refresh now").apply {
                        addActionListener {
                            manager.pollInteractions()
                            refreshTables()
                        }
                    })
                    add(Box.createHorizontalStrut(Design.Spacing.SM))
                    add(statusLabel.apply {
                        font = Design.Typography.bodyMedium
                        foreground = Design.Colors.onSurfaceVariant
                    })
                }
            )
        }

        val payloadsTable = JTable(payloadModel).apply {
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            preferredScrollableViewportSize = Dimension(0, 180)
        }
        val interactionsTable = JTable(interactionModel).apply {
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            preferredScrollableViewportSize = Dimension(0, 220)
        }

        val split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JPanel(BorderLayout()).apply {
                border = BorderFactory.createTitledBorder("Generated payloads")
                add(JScrollPane(payloadsTable), BorderLayout.CENTER)
            },
            JPanel(BorderLayout()).apply {
                border = BorderFactory.createTitledBorder("Interactions")
                add(JScrollPane(interactionsTable), BorderLayout.CENTER)
            }
        ).apply {
            resizeWeight = 0.45
        }

        add(header, BorderLayout.NORTH)
        add(split, BorderLayout.CENTER)
    }

    private fun refreshTables() {
        SwingUtilities.invokeLater {
            payloadModel.rowCount = 0
            interactionModel.rowCount = 0

            val formatter = SimpleDateFormat("HH:mm:ss")
            manager.getPayloads().forEach { record ->
                payloadModel.addRow(
                    arrayOf(
                        record.payload,
                        record.payloadId,
                        formatter.format(Date(record.createdAtMs))
                    )
                )
            }

            manager.getInteractions().forEach { record ->
                interactionModel.addRow(
                    arrayOf(
                        record.type,
                        record.clientIp,
                        record.timestamp,
                        record.summary
                    )
                )
            }

            statusLabel.text = "Payloads: ${manager.getPayloads().size}, interactions: ${manager.getInteractions().size}"
        }
    }
}

package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.CollaboratorPayload
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.SecretKey
import net.portswigger.mcp.schema.toSerializableForm
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.SwingUtilities

data class CollaboratorPayloadRecord(
    val payload: String,
    val payloadId: String,
    val secretKey: String,
    val customData: String?,
    val createdAtMs: Long,
)

data class CollaboratorInteractionRecord(
    val interactionId: String,
    val payloadId: String?,
    val secretKey: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val summary: String,
)

class CollaboratorManager(private val api: MontoyaApi) {
    private val payloads = CopyOnWriteArrayList<CollaboratorPayloadRecord>()
    private val interactions = CopyOnWriteArrayList<CollaboratorInteractionRecord>()
    private val knownInteractionIds = mutableSetOf<String>()
    private val lock = Any()

    private val polling = AtomicBoolean(true)
    private val poller = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "burp-mcp-collaborator-poller").apply { isDaemon = true }
    }

    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    init {
        poller.scheduleWithFixedDelay({ pollInteractions() }, 2, 3, TimeUnit.SECONDS)
    }

    fun shutdown() {
        polling.set(false)
        poller.shutdownNow()
    }

    fun addListener(listener: () -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: () -> Unit) {
        listeners.remove(listener)
    }

    fun generatePayload(customData: String?): Pair<CollaboratorPayload, CollaboratorClient> {
        val client = api.collaborator().createClient()
        val payload = if (customData != null) {
            client.generatePayload(customData)
        } else {
            client.generatePayload()
        }

        val record = CollaboratorPayloadRecord(
            payload = payload.toString(),
            payloadId = payload.id().toString(),
            secretKey = client.secretKey.toString(),
            customData = customData,
            createdAtMs = System.currentTimeMillis(),
        )
        payloads.add(0, record)
        notifyListeners()
        return payload to client
    }

    fun restoreClient(secretKey: String): CollaboratorClient {
        return api.collaborator().restoreClient(SecretKey.secretKey(secretKey))
    }

    fun getPayloads(): List<CollaboratorPayloadRecord> = payloads.toList()

    fun getInteractions(): List<CollaboratorInteractionRecord> = interactions.toList()

    fun pollInteractions() {
        if (!polling.get()) return

        val secretKeys = payloads.map { it.secretKey }.distinct()
        if (secretKeys.isEmpty()) return

        var changed = false
        for (secretKey in secretKeys) {
            val client = runCatching { restoreClient(secretKey) }.getOrNull() ?: continue
            val newInteractions = client.getAllInteractions()
            for (interaction in newInteractions) {
                if (recordInteraction(interaction, secretKey)) {
                    changed = true
                }
            }
        }

        if (changed) {
            notifyListeners()
        }
    }

    private fun recordInteraction(interaction: Interaction, secretKey: String): Boolean {
        val id = interaction.id().toString()
        synchronized(lock) {
            if (!knownInteractionIds.add(id)) return false
        }

        val details = interaction.toSerializableForm()
        val summary = buildString {
            append(details.type)
            append(" from ")
            append(details.clientIp)
            details.httpDetails?.request?.let { append(" — HTTP") }
            details.dnsDetails?.let { append(" — DNS ${it.queryType}") }
            details.smtpDetails?.let { append(" — SMTP") }
        }

        interactions.add(
            0,
            CollaboratorInteractionRecord(
                interactionId = id,
                payloadId = interaction.id().toString(),
                secretKey = secretKey,
                type = details.type,
                timestamp = details.timestamp,
                clientIp = details.clientIp,
                summary = summary,
            )
        )
        return true
    }

    private fun notifyListeners() {
        SwingUtilities.invokeLater {
            listeners.forEach { listener ->
                runCatching { listener() }
            }
        }
    }
}

package xyz.mcxross.vortex.vortex

import androidx.compose.runtime.Composable
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class StoredCommitmentEvent(
  val index: String,
  val commitment: String,
  val encryptedOutputBase64: String,
)

@Serializable data class StoredUtxo(val amount: String, val blinding: String, val index: String)

@Serializable
data class InboxState(
  val cursor: String? = null,
  val hasNext: Boolean = true,
  val commitments: List<StoredCommitmentEvent> = emptyList(),
  val utxos: List<StoredUtxo> = emptyList(),
)

class VortexStore(private val kv: KeyValueStore) {
  private val json = Json { ignoreUnknownKeys = true }

  fun loadInboxState(): InboxState? {
    val raw = kv.getString(KEY_INBOX) ?: return null
    return runCatching { json.decodeFromString(InboxState.serializer(), raw) }.getOrNull()
  }

  fun saveInboxState(state: InboxState) {
    val raw = json.encodeToString(InboxState.serializer(), state)
    kv.putString(KEY_INBOX, raw)
  }

  fun loadRegistryId(): String? = kv.getString(KEY_REGISTRY)

  fun saveRegistryId(registryId: String) {
    kv.putString(KEY_REGISTRY, registryId)
  }

  companion object {
    private const val KEY_INBOX = "vortex_inbox_state"
    private const val KEY_REGISTRY = "vortex_registry_id"
  }
}

interface KeyValueStore {
  fun getString(key: String): String?

  fun putString(key: String, value: String)
}

@Composable expect fun rememberVortexStore(): VortexStore

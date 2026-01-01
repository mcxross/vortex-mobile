package xyz.mcxross.vortex

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jetbrains.compose.resources.ExperimentalResourceApi
import vortex_mobile.composeapp.generated.resources.Res
import xyz.mcxross.ksui.Sui
import xyz.mcxross.ksui.model.Network
import xyz.mcxross.ksui.model.SuiConfig
import xyz.mcxross.ksui.model.SuiSettings
import xyz.mcxross.vortex.ui.VortexColorScheme
import xyz.mcxross.vortex.ui.VortexTerminalBg
import xyz.mcxross.vortex.ui.components.InlineStatus
import xyz.mcxross.vortex.ui.components.OperationStatus
import xyz.mcxross.vortex.ui.components.PrimaryActionButton
import xyz.mcxross.vortex.ui.components.SecondaryActionButton
import xyz.mcxross.vortex.ui.components.SectionCard
import xyz.mcxross.vortex.ui.components.StatusKind
import xyz.mcxross.vortex.ui.components.VortexTextField
import xyz.mcxross.vortex.utils.PACKAGE_ID
import xyz.mcxross.vortex.utils.VORTEX_POOL_ID
import xyz.mcxross.vortex.utils.acc
import xyz.mcxross.vortex.vortex.InboxState
import xyz.mcxross.vortex.vortex.StoredUtxo
import xyz.mcxross.vortex.vortex.Utxo
import xyz.mcxross.vortex.vortex.VortexClient
import xyz.mcxross.vortex.vortex.VortexKeypair
import xyz.mcxross.vortex.vortex.rememberVortexStore

@OptIn(ExperimentalResourceApi::class)
@Composable
fun App() {
  val scope = rememberCoroutineScope()
  val clipboardManager = LocalClipboardManager.current

  val defaultPrivateKey =
    "16954148715775892023035542296152792347617295291215951342474805784265045587453"
  val defaultRecipientKeypair = VortexKeypair(defaultPrivateKey)
  var amountText by remember { mutableStateOf("1000000") }
  var privateKeyText by remember { mutableStateOf(defaultPrivateKey) }
  var transferAmountText by remember { mutableStateOf("1000000") }
  var recipientPublicKeyText by remember { mutableStateOf(defaultRecipientKeypair.publicKey) }
  var recipientEncryptionKeyText by remember {
    mutableStateOf(defaultRecipientKeypair.encryptionKey)
  }
  var registryIdText by remember {
    mutableStateOf("0xf2c11c297e0581e0279714f6ba47e26d03d9a70756036fab5882ebc0f1d2b3b1")
  }
  var logs by remember { mutableStateOf("Waiting for user input...") }
  var isProcessing by remember { mutableStateOf(false) }
  var isDepositRunning by remember { mutableStateOf(false) }
  var isTransferRunning by remember { mutableStateOf(false) }
  var isRegistryRunning by remember { mutableStateOf(false) }
  var isInboxRunning by remember { mutableStateOf(false) }
  var provingKey by remember { mutableStateOf<ByteArray?>(null) }
  var lastDigest by remember { mutableStateOf("") }
  var inboxUtxos by remember { mutableStateOf<List<Utxo>>(emptyList()) }
  var inboxCursor by remember { mutableStateOf<String?>(null) }
  var inboxHasNext by remember { mutableStateOf(true) }
  var depositStatus by remember {
    mutableStateOf(OperationStatus("Deposit", "Idle", StatusKind.Idle))
  }
  var transferStatus by remember {
    mutableStateOf(OperationStatus("Private Transfer", "Idle", StatusKind.Idle))
  }
  var registryStatus by remember {
    mutableStateOf(OperationStatus("Registry", "Idle", StatusKind.Idle))
  }
  var inboxStatus by remember { mutableStateOf(OperationStatus("Inbox", "Idle", StatusKind.Idle)) }
  val store = rememberVortexStore()

  LaunchedEffect(Unit) {
    store.loadRegistryId()?.let { registryIdText = it }
    store.loadInboxState()?.let { state ->
      inboxCursor = state.cursor
      inboxHasNext = state.hasNext
      inboxUtxos =
        state.utxos.map {
          Utxo(
            amount = BigInteger.parseString(it.amount),
            blinding = BigInteger.parseString(it.blinding),
            index = BigInteger.parseString(it.index),
            keypair = VortexKeypair(privateKeyText),
          )
        }
    }
  }

  LaunchedEffect(Unit) {
    withContext(Dispatchers.Default) {
      try {
        provingKey = Res.readBytes("files/proving_key.bin")
      } catch (e: Exception) {
        logs = "❌ Failed to load proving key: ${e.message}"
        depositStatus = OperationStatus("Deposit", "Failed to load proving key.", StatusKind.Error)
      }
    }
  }

  MaterialTheme(colorScheme = VortexColorScheme) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
      Column(
        modifier =
          Modifier.fillMaxSize()
            .systemBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
      ) {
        Text(
          text = "Vortex Shield",
          style = MaterialTheme.typography.headlineLarge,
          fontWeight = FontWeight.ExtraBold,
          color = MaterialTheme.colorScheme.primary,
          letterSpacing = 1.5.sp,
        )
        Text(
          text = "Private Transactions on Sui",
          style = MaterialTheme.typography.titleMedium,
          color = MaterialTheme.colorScheme.secondary,
          modifier = Modifier.padding(top = 4.dp),
        )

        Spacer(modifier = Modifier.height(48.dp))

        VortexTextField(
          value = amountText,
          onValueChange = { amountText = it },
          label = "Amount (MIST)",
          keyboardType = KeyboardType.Number,
          enabled = !isProcessing,
        )

        Spacer(modifier = Modifier.height(16.dp))

        VortexTextField(
          value = privateKeyText,
          onValueChange = { privateKeyText = it },
          label = "Vortex Private Key",
          enabled = !isProcessing,
          monospace = true,
        )

        Spacer(modifier = Modifier.height(32.dp))

        PrimaryActionButton(
          text = if (isProcessing) "Processing..." else "DEPOSIT FUNDS",
          onClick = {
            if (provingKey == null) {
              logs = "⚠️ Proving Key not loaded yet. Please wait."
              return@PrimaryActionButton
            }

            isProcessing = true
            isDepositRunning = true
            lastDigest = ""
            logs = "🚀 Starting Deposit..."
            depositStatus = OperationStatus("Deposit", "Starting...", StatusKind.Running)

            scope.launch {
              try {
                val sui = Sui(SuiConfig(SuiSettings(network = Network.TESTNET)))
                val vortex = VortexClient(sui, PACKAGE_ID, VORTEX_POOL_ID, provingKey!!)

                withContext(Dispatchers.Default) {
                  vortex.deposit(
                    account = acc,
                    amount = amountText.toULong(),
                    privateKey = privateKeyText,
                    onStatus = { status ->
                      logs = status
                      depositStatus = depositStatus.copy(detail = status)
                      if (status.contains("Digest:")) {
                        val extracted = status.substringAfter("Digest:").trim()
                        if (extracted.isNotEmpty()) {
                          lastDigest = extracted
                        }
                      }
                    },
                  )
                }
                depositStatus = OperationStatus("Deposit", "Deposit completed.", StatusKind.Success)
              } catch (e: Exception) {
                logs = "❌ Error: ${e.message}\n${e.stackTraceToString().take(300)}..."
                depositStatus =
                  OperationStatus("Deposit", "Deposit failed: ${e.message}", StatusKind.Error)
              } finally {
                isProcessing = false
                isDepositRunning = false
              }
            }
          },
          enabled = !isProcessing && provingKey != null,
          height = 56.dp,
        )

        Spacer(modifier = Modifier.height(12.dp))
        if (depositStatus.kind != StatusKind.Idle || isDepositRunning) {
          InlineStatus(status = depositStatus, isProcessing = isDepositRunning)
        }

        Spacer(modifier = Modifier.height(32.dp))

        SectionCard(title = "Private Transfer") {
          VortexTextField(
            value = transferAmountText,
            onValueChange = { transferAmountText = it },
            label = "Amount (MIST)",
            keyboardType = KeyboardType.Number,
            enabled = !isProcessing,
          )

          Spacer(modifier = Modifier.height(12.dp))

          VortexTextField(
            value = recipientPublicKeyText,
            onValueChange = { recipientPublicKeyText = it },
            label = "Recipient Public Key",
            enabled = !isProcessing,
            monospace = true,
          )

          Spacer(modifier = Modifier.height(12.dp))

          VortexTextField(
            value = recipientEncryptionKeyText,
            onValueChange = { recipientEncryptionKeyText = it },
            label = "Recipient Encryption Key",
            enabled = !isProcessing,
            monospace = true,
          )

          Spacer(modifier = Modifier.height(16.dp))

          PrimaryActionButton(
            text = "PRIVATE TRANSFER",
            onClick = {
              if (provingKey == null) {
                logs = "⚠️ Proving Key not loaded yet. Please wait."
                return@PrimaryActionButton
              }
              if (recipientPublicKeyText.isBlank() || recipientEncryptionKeyText.isBlank()) {
                logs = "⚠️ Recipient keys are required."
                return@PrimaryActionButton
              }

              isProcessing = true
              isTransferRunning = true
              lastDigest = ""
              logs = "🔒 Starting Private Transfer..."
              transferStatus =
                OperationStatus("Private Transfer", "Starting...", StatusKind.Running)

              scope.launch {
                try {
                  val sui = Sui(SuiConfig(SuiSettings(network = Network.TESTNET)))
                  val vortex = VortexClient(sui, PACKAGE_ID, VORTEX_POOL_ID, provingKey!!)
                  val senderKeypair = VortexKeypair(privateKeyText)

                  withContext(Dispatchers.Default) {
                    vortex.privateTransfer(
                      account = acc,
                      amount = transferAmountText.toULong(),
                      senderKeypair = senderKeypair,
                      recipientPublicKey = recipientPublicKeyText.trim(),
                      recipientEncryptionKey = recipientEncryptionKeyText.trim(),
                      onStatus = { status ->
                        logs = status
                        transferStatus = transferStatus.copy(detail = status)
                        if (status.contains("Digest:")) {
                          val extracted = status.substringAfter("Digest:").trim()
                          if (extracted.isNotEmpty()) {
                            lastDigest = extracted
                          }
                        }
                      },
                    )
                  }
                  transferStatus =
                    OperationStatus("Private Transfer", "Transfer completed.", StatusKind.Success)
                } catch (e: Exception) {
                  logs =
                    "❌ Error: ${e.message}\n${
                                        e.stackTraceToString().take(300)
                                    }..."
                  transferStatus =
                    OperationStatus(
                      "Private Transfer",
                      "Transfer failed: ${e.message}",
                      StatusKind.Error,
                    )
                } finally {
                  isProcessing = false
                  isTransferRunning = false
                }
              }
            },
            enabled = !isProcessing && provingKey != null,
          )

          Spacer(modifier = Modifier.height(12.dp))
          if (transferStatus.kind != StatusKind.Idle || isTransferRunning) {
            InlineStatus(status = transferStatus, isProcessing = isTransferRunning)
          }
        }

        Spacer(modifier = Modifier.height(32.dp))

        SectionCard(title = "Receive") {
          VortexTextField(
            value = registryIdText,
            onValueChange = { registryIdText = it },
            label = "Registry Object ID",
            enabled = !isProcessing,
            monospace = true,
          )

          Spacer(modifier = Modifier.height(12.dp))

          SecondaryActionButton(
            text = "AUTO-FETCH REGISTRY ID",
            onClick = {
              isProcessing = true
              isRegistryRunning = true
              logs = "🔎 Resolving registry ID..."
              registryStatus =
                OperationStatus("Registry Lookup", "Fetching registry ID...", StatusKind.Running)
              scope.launch {
                try {
                  val sui = Sui(SuiConfig(SuiSettings(network = Network.TESTNET)))
                  val vortex = VortexClient(sui, PACKAGE_ID, VORTEX_POOL_ID, provingKey!!)
                  val resolved = withContext(Dispatchers.Default) { vortex.resolveRegistryId() }
                  if (resolved != null) {
                    registryIdText = resolved
                    store.saveRegistryId(resolved)
                    logs = "✅ Registry ID resolved."
                    registryStatus =
                      OperationStatus(
                        "Registry Lookup",
                        "Registry ID resolved.",
                        StatusKind.Success,
                      )
                  } else {
                    logs = "⚠️ Registry ID not found on-chain."
                    registryStatus =
                      OperationStatus("Registry Lookup", "Registry ID not found.", StatusKind.Error)
                  }
                } catch (e: Exception) {
                  logs =
                    "❌ Error: ${e.message}\n${
                                        e.stackTraceToString().take(300)
                                    }..."
                  registryStatus =
                    OperationStatus(
                      "Registry Lookup",
                      "Lookup failed: ${e.message}",
                      StatusKind.Error,
                    )
                } finally {
                  isProcessing = false
                  isRegistryRunning = false
                }
              }
            },
            enabled = !isProcessing && provingKey != null && inboxHasNext,
          )

          Spacer(modifier = Modifier.height(12.dp))

          PrimaryActionButton(
            text = "REGISTER ENCRYPTION KEY",
            onClick = {
              if (registryIdText.isBlank()) {
                logs = "⚠️ Registry object ID is required."
                return@PrimaryActionButton
              }

              isProcessing = true
              isRegistryRunning = true
              lastDigest = ""
              logs = "🔐 Registering encryption key..."
              registryStatus =
                OperationStatus(
                  "Register Encryption Key",
                  "Submitting registration...",
                  StatusKind.Running,
                )

              scope.launch {
                try {
                  val sui = Sui(SuiConfig(SuiSettings(network = Network.TESTNET)))
                  val vortex = VortexClient(sui, PACKAGE_ID, VORTEX_POOL_ID, provingKey!!)
                  val senderKeypair = VortexKeypair(privateKeyText)

                  withContext(Dispatchers.Default) {
                    vortex.registerEncryptionKey(
                      account = acc,
                      registryObjectId = registryIdText.trim(),
                      keypair = senderKeypair,
                      onStatus = { status ->
                        logs = status
                        registryStatus = registryStatus.copy(detail = status)
                        if (status.contains("Digest:")) {
                          val extracted = status.substringAfter("Digest:").trim()
                          if (extracted.isNotEmpty()) {
                            lastDigest = extracted
                          }
                        }
                      },
                    )
                  }
                  store.saveRegistryId(registryIdText.trim())
                  registryStatus =
                    OperationStatus(
                      "Register Encryption Key",
                      "Encryption key registered.",
                      StatusKind.Success,
                    )
                } catch (e: Exception) {
                  logs =
                    "❌ Error: ${e.message}\n${
                                        e.stackTraceToString().take(300)
                                    }..."
                  registryStatus =
                    OperationStatus(
                      "Register Encryption Key",
                      "Registration failed: ${e.message}",
                      StatusKind.Error,
                    )
                } finally {
                  isProcessing = false
                  isRegistryRunning = false
                }
              }
            },
            enabled = !isProcessing && provingKey != null,
          )

          Spacer(modifier = Modifier.height(12.dp))
          if (registryStatus.kind != StatusKind.Idle || isRegistryRunning) {
            InlineStatus(status = registryStatus, isProcessing = isRegistryRunning)
          }

          Spacer(modifier = Modifier.height(16.dp))

          SecondaryActionButton(
            text = "REFRESH INBOX",
            onClick = {
              isProcessing = true
              isInboxRunning = true
              logs = "📥 Scanning for received UTXOs..."
              inboxStatus =
                OperationStatus("Inbox Refresh", "Scanning events...", StatusKind.Running)

              scope.launch {
                try {
                  val sui = Sui(SuiConfig(SuiSettings(network = Network.TESTNET)))
                  val vortex = VortexClient(sui, PACKAGE_ID, VORTEX_POOL_ID, provingKey!!)
                  val senderKeypair = VortexKeypair(privateKeyText)

                  val maxPages = 5
                  var pageCursor: String? = null
                  var hasNext = true
                  val collected = mutableListOf<Utxo>()
                  var pagesFetched = 0

                  while (hasNext && pagesFetched < maxPages) {
                    val page =
                      withContext(Dispatchers.Default) {
                        vortex.scanCommitmentEventsPage(after = pageCursor)
                      }
                    val utxos =
                      withContext(Dispatchers.Default) {
                        vortex.getUnspentUtxos(page.events, senderKeypair)
                      }
                    collected += utxos
                    pageCursor = page.nextCursor
                    hasNext = page.hasNext
                    pagesFetched += 1
                    if (collected.isNotEmpty()) break
                  }

                  inboxUtxos = collected
                  inboxCursor = pageCursor
                  inboxHasNext = hasNext
                  val total = collected.fold(BigInteger.ZERO) { acc, utxo -> acc + utxo.amount }
                  logs = "✅ Inbox refreshed. UTXOs: ${collected.size}, Total: ${total} MIST"
                  inboxStatus =
                    OperationStatus("Inbox Refresh", "UTXOs: ${collected.size}", StatusKind.Success)
                  store.saveInboxState(
                    InboxState(
                      cursor = inboxCursor,
                      hasNext = inboxHasNext,
                      utxos =
                        collected.map {
                          StoredUtxo(
                            amount = it.amount.toString(),
                            blinding = it.blinding.toString(),
                            index = it.index.toString(),
                          )
                        },
                    )
                  )
                } catch (e: Exception) {
                  logs =
                    "❌ Error: ${e.message}\n${
                                        e.stackTraceToString().take(300)
                                    }..."
                  inboxStatus =
                    OperationStatus(
                      "Inbox Refresh",
                      "Refresh failed: ${e.message}",
                      StatusKind.Error,
                    )
                } finally {
                  isProcessing = false
                  isInboxRunning = false
                }
              }
            },
            enabled = !isProcessing && provingKey != null,
          )

          Spacer(modifier = Modifier.height(12.dp))

          SecondaryActionButton(
            text = "LOAD MORE",
            onClick = {
              if (!inboxHasNext) {
                logs = "ℹ️ No more pages."
                return@SecondaryActionButton
              }

              isProcessing = true
              isInboxRunning = true
              logs = "📦 Loading more..."
              inboxStatus =
                OperationStatus("Inbox Pagination", "Loading next page...", StatusKind.Running)

              scope.launch {
                try {
                  val sui = Sui(SuiConfig(SuiSettings(network = Network.TESTNET)))
                  val vortex = VortexClient(sui, PACKAGE_ID, VORTEX_POOL_ID, provingKey!!)
                  val senderKeypair = VortexKeypair(privateKeyText)

                  val page =
                    withContext(Dispatchers.Default) {
                      vortex.scanCommitmentEventsPage(after = inboxCursor)
                    }
                  val utxos =
                    withContext(Dispatchers.Default) {
                      vortex.getUnspentUtxos(page.events, senderKeypair)
                    }

                  inboxUtxos = inboxUtxos + utxos
                  inboxCursor = page.nextCursor
                  inboxHasNext = page.hasNext
                  store.saveInboxState(
                    InboxState(
                      cursor = inboxCursor,
                      hasNext = inboxHasNext,
                      utxos =
                        inboxUtxos.map {
                          StoredUtxo(
                            amount = it.amount.toString(),
                            blinding = it.blinding.toString(),
                            index = it.index.toString(),
                          )
                        },
                    )
                  )
                  logs = "✅ Added ${utxos.size} more UTXOs."
                  inboxStatus =
                    OperationStatus(
                      "Inbox Pagination",
                      "Loaded ${utxos.size} more.",
                      StatusKind.Success,
                    )
                } catch (e: Exception) {
                  logs =
                    "❌ Error: ${e.message}\n${
                                        e.stackTraceToString().take(300)
                                    }..."
                  inboxStatus =
                    OperationStatus(
                      "Inbox Pagination",
                      "Pagination failed: ${e.message}",
                      StatusKind.Error,
                    )
                } finally {
                  isProcessing = false
                  isInboxRunning = false
                }
              }
            },
            enabled = !isProcessing && provingKey != null,
          )

          Spacer(modifier = Modifier.height(12.dp))
          if (inboxStatus.kind != StatusKind.Idle || isInboxRunning) {
            InlineStatus(status = inboxStatus, isProcessing = isInboxRunning)
          }

          if (inboxUtxos.isNotEmpty()) {
            Spacer(modifier = Modifier.height(12.dp))
            LazyColumn(modifier = Modifier.fillMaxWidth().height(220.dp)) {
              items(inboxUtxos) { utxo ->
                Text(
                  text = "• ${utxo.amount} MIST @ index ${utxo.index}",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurface,
                )
              }
            }
          }
        }

        Spacer(modifier = Modifier.height(32.dp))

        Card(
          modifier = Modifier.fillMaxWidth().height(200.dp),
          colors = CardDefaults.cardColors(containerColor = VortexTerminalBg),
          shape = RoundedCornerShape(8.dp),
          border = BorderStroke(1.dp, Color(0xFF333333)),
        ) {
          Box(modifier = Modifier.padding(16.dp)) {
            Text(
              text = logs,
              style = MaterialTheme.typography.bodySmall.copy(lineHeight = 16.sp),
              fontFamily = FontFamily.Monospace,
              color = if (logs.contains("Error")) Color(0xFFFF5252) else Color(0xFFEEEEEE),
            )
          }
        }

        Spacer(modifier = Modifier.height(12.dp))

        SecondaryActionButton(
          text = "Copy Logs",
          onClick = {
            clipboardManager.setText(AnnotatedString(logs))
            logs += "\n\n📋 Logs copied to clipboard!"
          },
        )

        if (lastDigest.isNotEmpty()) {
          Spacer(modifier = Modifier.height(16.dp))
          SecondaryActionButton(
            text = "Copy Transaction Digest",
            onClick = {
              clipboardManager.setText(AnnotatedString(lastDigest))
              logs += "\n\n📋 Digest copied to clipboard!"
            },
          )
        }
      }
    }
  }
}

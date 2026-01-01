package xyz.mcxross.vortex.vortex

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.collections.get
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import uniffi.vortex.poseidon1
import uniffi.vortex.poseidon3
import uniffi.vortex.poseidon4
import uniffi.vortex.prove
import xyz.mcxross.bcs.Bcs
import xyz.mcxross.ksui.Sui
import xyz.mcxross.ksui.account.Account
import xyz.mcxross.ksui.generated.ExecuteTransactionBlockMutation
import xyz.mcxross.ksui.generated.QueryEventsQuery
import xyz.mcxross.ksui.model.EventFilter
import xyz.mcxross.ksui.model.ExecuteTransactionBlockResponseOptions
import xyz.mcxross.ksui.model.ObjectDataOptions
import xyz.mcxross.ksui.ptb.Argument
import xyz.mcxross.ksui.ptb.ptb
import xyz.mcxross.ksui.util.compose
import xyz.mcxross.ksui.util.toTypeTag
import xyz.mcxross.vortex.utils.Bcs_

class VortexClient(
  private val sui: Sui,
  private val packageId: String,
  private val vortexPoolId: String,
  private val provingKey: ByteArray,
  private val registryId: String? = null,
) {

  private val BN254_FIELD_MODULUS =
    BigInteger.parseString(
      "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )

  suspend fun deposit(
    account: Account,
    amount: ULong,
    privateKey: String,
    onStatus: (String) -> Unit = { println(it) },
  ) {
    val amountStr = amount.toString()

    onStatus("(1/5) 🌐 Initializing & Fetching Root...")

    val cleanId = vortexPoolId.removePrefix("0x")
    val idBigInt = BigInteger.parseString(cleanId, 16)
    val vortexIdInt = idBigInt.mod(BN254_FIELD_MODULUS).toString()

    val realRoot = getCurrentRoot(account)
    println("ℹ️ Fetched Current Root: $realRoot")

    val zero = "0"

    onStatus("(2/5) 🔐 Preparing Zero-Knowledge Inputs...")

    val pubKey = poseidon1(privateKey)
    val blinding = Random.nextLong(0, 1_000_000_000).toString()

    val outputCommitment = poseidon4(listOf(amountStr, pubKey, blinding, vortexIdInt))

    val zeroCommitment = poseidon4(listOf(zero, pubKey, zero, vortexIdInt))

    val dummyPathIndex0 = "0"
    val dummyPathIndex1 = "0"

    val dummyBlinding0 = Random.nextLong(0, 1_000_000_000).toString()
    val dummyBlinding1 = Random.nextLong(0, 1_000_000_000).toString()

    val dummyInputCommitment0 = poseidon4(listOf(zero, pubKey, dummyBlinding0, vortexIdInt))
    val dummySignature0 = poseidon3(listOf(privateKey, dummyInputCommitment0, dummyPathIndex0))
    val dummyNullifier0 = poseidon3(listOf(dummyInputCommitment0, dummyPathIndex0, dummySignature0))

    val dummyInputCommitment1 = poseidon4(listOf(zero, pubKey, dummyBlinding1, vortexIdInt))
    val dummySignature1 = poseidon3(listOf(privateKey, dummyInputCommitment1, dummyPathIndex1))
    val dummyNullifier1 = poseidon3(listOf(dummyInputCommitment1, dummyPathIndex1, dummySignature1))

    val inputJson =
      buildJsonObject {
          put("vortex", vortexIdInt)
          put("root", realRoot)
          put("publicAmount", amountStr)

          put("inputNullifier0", dummyNullifier0)
          put("inputNullifier1", dummyNullifier1)

          put("outputCommitment0", outputCommitment)
          put("outputCommitment1", zeroCommitment)

          put("hashedAccountSecret", zero)
          put("accountSecret", zero)

          put("inPrivateKey0", privateKey)
          put("inAmount0", zero)
          put("inBlinding0", dummyBlinding0)
          put("inPathIndex0", dummyPathIndex0)
          put("inPrivateKey1", privateKey)
          put("inAmount1", zero)
          put("inBlinding1", dummyBlinding1)
          put("inPathIndex1", dummyPathIndex1)

          put("outPublicKey0", pubKey)
          put("outAmount0", amountStr)
          put("outBlinding0", blinding)
          put("outPublicKey1", pubKey)
          put("outAmount1", zero)
          put("outBlinding1", zero)

          putJsonArray("merklePath0") { repeat(26) { add(buildJsonArrayOfStrings("0", "0")) } }
          putJsonArray("merklePath1") { repeat(26) { add(buildJsonArrayOfStrings("0", "0")) } }
        }
        .toString()

    onStatus("(3/5) ⚡ Generating ZK Proof (This takes ~20s)...")

    val proofOutputJson = prove(inputJson, provingKey)
    val proofData = Json.parseToJsonElement(proofOutputJson).jsonObject

    val publicInputs = proofData["publicInputs"]!!.jsonArray.map { it.jsonPrimitive.content }
    val proofSerializedHex = proofData["proofSerializedHex"]!!.jsonPrimitive.content
    val proofBytes = hexStringToByteArray(proofSerializedHex)

    onStatus("(4/5) 📦 Building Sui Transaction...")

    val gasBudget = 15_000_000UL
    ensureGasCoinBalance(account, amount, gasBudget)

    val senderKeypair = VortexKeypair(privateKey)
    val encryptedOutput0 =
      VortexCrypto.encryptUtxoFor(UtxoPayload(amountStr, blinding), senderKeypair.encryptionKey)
    val encryptedOutput1 =
      VortexCrypto.encryptUtxoFor(UtxoPayload(zero, zero), senderKeypair.encryptionKey)

    val tx = ptb {
      val coinInput = splitCoins {
        coin = Argument.GasCoin
        into = +pure(amount)
      }

      val extData = moveCall {
        target = "$packageId::vortex_ext_data::new"
        arguments =
          listOf(
            pure(amount),
            pure(true),
            address(account),
            pure(0UL),
            pure(Bcs.encodeToByteArray(encryptedOutput0)),
            pure(Bcs.encodeToByteArray(encryptedOutput1)),
          )
      }

      val proof = moveCall {
        target = "$packageId::vortex_proof::new"
        typeArguments = +"0x2::sui::SUI".toTypeTag()
        arguments =
          listOf(
            pure(hexStringToByteArray(vortexPoolId.removePrefix("0x"))),
            pure(Bcs.encodeToByteArray(proofBytes)),
            pure(Bcs_.serializeU256(publicInputs[1])),
            pure(Bcs_.serializeU256(publicInputs[2])),
            pure(Bcs_.serializeU256(publicInputs[3])),
            pure(Bcs_.serializeU256(publicInputs[4])),
            pure(Bcs_.serializeU256(publicInputs[5])),
            pure(Bcs_.serializeU256(publicInputs[6])),
          )
      }

      val resultCoin = moveCall {
        target = "$packageId::vortex::transact"
        typeArguments = +"0x2::sui::SUI".toTypeTag()
        arguments = listOf(`object`(vortexPoolId), coinInput[0], proof, extData)
      }

      transferObjects {
        objects = listOf(resultCoin)
        to = address(account)
      }
    }

    onStatus("(5/5) 🚀 Submitting to Network...")

    val response =
      sui.signAndExecuteTransactionBlock(
        signer = account,
        ptb = tx,
        gasBudget = gasBudget,
        options = ExecuteTransactionBlockResponseOptions(showEffects = true, showEvents = true),
      )

    val digest = extractDigest(response.unwrap(), "deposit")
    onStatus("✅ Deposit Complete!\nDigest: $digest")
  }

  suspend fun privateTransfer(
    account: Account,
    amount: ULong,
    senderKeypair: VortexKeypair,
    recipientPublicKey: String,
    recipientEncryptionKey: String,
    onStatus: (String) -> Unit = { println(it) },
  ) {
    val amountBig = BigInteger.parseString(amount.toString())
    val amountStr = amountBig.toString()
    val vortexIdInt = vortexIdField()

    onStatus("(1/5) 🌐 Scanning commitments...")
    val events = scanCommitmentEvents()
    val tree = VortexMerkleTree.Companion.fromEvents(events)
    val unspent = getUnspentUtxos(events, senderKeypair)
    val totalBalance = unspent.fold(BigInteger.ZERO) { acc, utxo -> acc + utxo.amount }
    onStatus("📥 Found ${unspent.size} UTXOs. Total: $totalBalance MIST")

    onStatus("(2/5) 🧾 Selecting inputs...")
    val inputs = selectInputs(unspent, amountBig)
    val inputUtxo0 = inputs.first
    val inputUtxo1 = inputs.second
    val input0 = InputWitness.fromUtxo(inputUtxo0)
    val input1 = InputWitness.fromUtxo(inputUtxo1)

    val totalIn = inputUtxo0.amount + inputUtxo1.amount
    val change = totalIn - amountBig

    val output0 =
      OutputWitness(
        publicKey = recipientPublicKey,
        amount = amountBig,
        blinding = Utxo.Companion.randomBlinding(),
      )
    val output1 =
      OutputWitness(
        publicKey = senderKeypair.publicKey,
        amount = change,
        blinding = Utxo.Companion.randomBlinding(),
      )

    val maxIndex = 1L shl MERKLE_TREE_LEVEL
    if (inputUtxo0.amount != BigInteger.ZERO) {
      require(inputUtxo0.index.toString().toLong() < maxIndex) {
        "Input 0 index exceeds tree capacity (>= 2^${MERKLE_TREE_LEVEL})"
      }
    }
    if (inputUtxo1.amount != BigInteger.ZERO) {
      require(inputUtxo1.index.toString().toLong() < maxIndex) {
        "Input 1 index exceeds tree capacity (>= 2^${MERKLE_TREE_LEVEL})"
      }
    }

    val path0 =
      if (inputUtxo0.amount == BigInteger.ZERO) {
        zeroMerklePath()
      } else {
        tree.path(inputUtxo0.index.toString().toInt())
      }
    val path1 =
      if (inputUtxo1.amount == BigInteger.ZERO) {
        zeroMerklePath()
      } else {
        tree.path(inputUtxo1.index.toString().toInt())
      }

    onStatus("(3/5) ⚡ Generating ZK Proof...")
    val proofInputJson =
      buildProofInputJson(
        vortex = vortexIdInt,
        root = tree.root(),
        publicAmount = "0",
        input0 = input0,
        input1 = input1,
        output0 = output0,
        output1 = output1,
        merklePath0 = path0,
        merklePath1 = path1,
      )

    val proofOutputJson = prove(proofInputJson, provingKey)
    val proofData = Json.parseToJsonElement(proofOutputJson).jsonObject
    val publicInputs = proofData["publicInputs"]!!.jsonArray.map { it.jsonPrimitive.content }
    val proofSerializedHex = proofData["proofSerializedHex"]!!.jsonPrimitive.content
    val proofBytes = hexStringToByteArray(proofSerializedHex)

    onStatus("(4/5) 📦 Building Sui Transaction...")

    val encryptedOutput0 =
      VortexCrypto.encryptUtxoFor(
        UtxoPayload(amountStr, output0.blinding.toString()),
        recipientEncryptionKey,
      )
    val encryptedOutput1 =
      VortexCrypto.encryptUtxoFor(
        UtxoPayload(change.toString(), output1.blinding.toString()),
        senderKeypair.encryptionKey,
      )

    val tx = ptb {
      val coinInput = splitCoins {
        coin = Argument.GasCoin
        into = +pure(0UL)
      }

      val extData = moveCall {
        target = "$packageId::vortex_ext_data::new"
        arguments =
          listOf(
            pure(0UL),
            pure(true),
            address(account),
            pure(0UL),
            pure(Bcs.encodeToByteArray(encryptedOutput0)),
            pure(Bcs.encodeToByteArray(encryptedOutput1)),
          )
      }

      val proof = moveCall {
        target = "$packageId::vortex_proof::new"
        typeArguments = +"0x2::sui::SUI".toTypeTag()
        arguments =
          listOf(
            pure(hexStringToByteArray(vortexPoolId.removePrefix("0x"))),
            pure(Bcs.encodeToByteArray(proofBytes)),
            pure(Bcs_.serializeU256(publicInputs[1])),
            pure(Bcs_.serializeU256(publicInputs[2])),
            pure(Bcs_.serializeU256(publicInputs[3])),
            pure(Bcs_.serializeU256(publicInputs[4])),
            pure(Bcs_.serializeU256(publicInputs[5])),
            pure(Bcs_.serializeU256(publicInputs[6])),
          )
      }

      val resultCoin = moveCall {
        target = "$packageId::vortex::transact"
        typeArguments = +"0x2::sui::SUI".toTypeTag()
        arguments = listOf(`object`(vortexPoolId), coinInput[0], proof, extData)
      }

      transferObjects {
        objects = listOf(resultCoin)
        to = address(account)
      }
    }

    onStatus("(5/5) 🚀 Submitting to Network...")
    val response =
      sui.signAndExecuteTransactionBlock(
        signer = account,
        ptb = tx,
        gasBudget = 15_000_000UL,
        options = ExecuteTransactionBlockResponseOptions(showEffects = true, showEvents = true),
      )

    val digest = extractDigest(response.unwrap(), "private transfer")
    onStatus("✅ Private Transfer Complete!\nDigest: $digest")
  }

  suspend fun scanCommitmentEvents(limitPerPage: Int = 50): List<CommitmentEvent> {
    val all = mutableListOf<CommitmentEvent>()
    var cursor: String? = null
    var hasNext = true
    val type = "$packageId::vortex_events::NewCommitment<0x2::sui::SUI>"

    while (hasNext) {
      val data =
        sui
          .queryEvents(filter = EventFilter(type = type), after = cursor, first = limitPerPage)
          .unwrap()

      val events = data?.events ?: break
      all.addAll(parseCommitmentEvents(events))
      val pageInfo = events.pageInfo
      hasNext = pageInfo.hasNextPage
      cursor = pageInfo.endCursor
    }

    return all
  }

  suspend fun scanCommitmentEventsPage(after: String?, limitPerPage: Int = 50): CommitmentPage {
    val type = "$packageId::vortex_events::NewCommitment<0x2::sui::SUI>"
    val data =
      sui
        .queryEvents(filter = EventFilter(type = type), after = after, first = limitPerPage)
        .unwrap()
    val events = data?.events ?: return CommitmentPage(emptyList(), null, false)
    val parsed = parseCommitmentEvents(events)
    val pageInfo = events.pageInfo
    return CommitmentPage(parsed, pageInfo.endCursor, pageInfo.hasNextPage)
  }

  suspend fun registerEncryptionKey(
    account: Account,
    registryObjectId: String,
    keypair: VortexKeypair,
    onStatus: (String) -> Unit = { println(it) },
  ) {
    onStatus("🔐 Registering encryption key...")
    val tx = ptb {
      moveCall {
        target = "$packageId::vortex::register"
        arguments = listOf(`object`(registryObjectId), pure(keypair.encryptionKey))
      }
    }

    val response =
      sui.signAndExecuteTransactionBlock(
        signer = account,
        ptb = tx,
        gasBudget = 5_000_000UL,
        options = ExecuteTransactionBlockResponseOptions(showEffects = true, showEvents = true),
      )

    val digest = extractDigest(response.unwrap(), "register encryption key")
    onStatus("✅ Encryption key registered!\nDigest: $digest")
  }

  suspend fun resolveRegistryId(): String? {
    val options = ObjectDataOptions(showContent = true, showType = true)
    val data = sui.getObject(vortexPoolId, options).unwrap()
    val json =
      data?.`object`?.rPC_OBJECT_FIELDS?.asMoveObject?.contents?.json as? Map<*, *> ?: return null
    val fields = json["fields"] as? Map<*, *> ?: return null
    findRegistryId(fields)?.let {
      return it
    }
    return findFirstObjectId(fields, setOf(vortexPoolId))
  }

  fun getUnspentUtxos(events: List<CommitmentEvent>, keypair: VortexKeypair): List<Utxo> {
    val utxos = mutableListOf<Utxo>()
    val maxIndex = 1L shl MERKLE_TREE_LEVEL
    for (event in events) {
      val payload = VortexCrypto.decryptUtxo(event.encryptedOutput, keypair.privateKey)
      if (payload != null) {
        if (event.index.toLong() >= maxIndex) continue
        val amount = BigInteger.parseString(payload.amount)
        val blinding = BigInteger.parseString(payload.blinding)
        val index = BigInteger.parseString(event.index.toString())
        utxos.add(Utxo(amount, blinding, index, keypair))
      }
    }
    return utxos
  }

  @OptIn(ExperimentalEncodingApi::class)
  private suspend fun getCurrentRoot(account: Account): String {

    val ptb = ptb {
      moveCall {
        target = "$packageId::vortex::root"
        typeArguments = +"0x2::sui::SUI".toTypeTag()
        arguments = listOf(`object`(vortexPoolId))
      }
    }

    val txBytes = ptb compose (account to 10_000_000UL)

    val res = sui.devInspectTransactionBlock(txBytes).unwrap()

    val base64Result =
      res?.simulateTransaction?.outputs?.firstOrNull()?.returnValues?.firstOrNull()?.value?.bcs
    requireNotNull(base64Result) { "Missing BCS return value for root() devInspect" }

    val bytes = Base64.decode(base64Result.toString())

    val bigEndianBytes = bytes.reversedArray()

    val u256Value = BigInteger.fromByteArray(bigEndianBytes, Sign.POSITIVE)

    return u256Value.toString()
  }

  private fun parseCommitmentEvents(events: QueryEventsQuery.Events): List<CommitmentEvent> {
    return events.nodes.mapNotNull { node ->
      parseCommitmentEventJson(node.rPC_EVENTS_FIELDS.contents?.json)
    }
  }

  private fun findRegistryId(fields: Map<*, *>): String? {
    val candidates =
      listOf("registry", "registry_id", "registryId", "registry_object", "registry_object_id")
    for (key in candidates) {
      val value = fields[key] as? String
      if (!value.isNullOrBlank()) {
        return value
      }
    }
    return null
  }

  private fun findFirstObjectId(value: Any?, skip: Set<String>): String? {
    return when (value) {
      is String -> {
        val trimmed = value.trim()
        if (trimmed.startsWith("0x") && trimmed.length >= 42 && trimmed !in skip) {
          trimmed
        } else {
          null
        }
      }
      is Map<*, *> -> {
        for ((_, nested) in value) {
          val found = findFirstObjectId(nested, skip)
          if (found != null) return found
        }
        null
      }
      is List<*> -> {
        for (nested in value) {
          val found = findFirstObjectId(nested, skip)
          if (found != null) return found
        }
        null
      }
      else -> null
    }
  }

  private fun selectInputs(unspent: List<Utxo>, target: BigInteger): Pair<Utxo, Utxo> {
    val sorted = unspent.sortedByDescending { it.amount }
    val available = sorted.fold(BigInteger.ZERO) { acc, utxo -> acc + utxo.amount }
    if (available < target) {
      throw IllegalStateException(
        "Insufficient balance for private transfer. Available: $available MIST, " +
          "Required: $target MIST. Deposit and refresh inbox first."
      )
    }
    var total = BigInteger.ZERO
    val selected = mutableListOf<Utxo>()
    for (utxo in sorted) {
      selected.add(utxo)
      total += utxo.amount
      if (total >= target || selected.size == 2) break
    }

    val input0 = selected.getOrNull(0) ?: dummyInput()
    val input1 = selected.getOrNull(1) ?: dummyInput()
    return input0 to input1
  }

  private fun dummyInput(): Utxo {
    return Utxo(
      amount = BigInteger.ZERO,
      blinding = Utxo.Companion.randomBlinding(),
      index = BigInteger.ZERO,
      keypair = VortexKeypair("0"),
    )
  }

  private fun zeroMerklePath(): List<Pair<String, String>> {
    return List(MERKLE_TREE_LEVEL) { "0" to "0" }
  }

  private fun buildProofInputJson(
    vortex: String,
    root: String,
    publicAmount: String,
    input0: InputWitness,
    input1: InputWitness,
    output0: OutputWitness,
    output1: OutputWitness,
    merklePath0: List<Pair<String, String>>,
    merklePath1: List<Pair<String, String>>,
  ): String {
    val input0Commitment =
      poseidon4(listOf(input0.amount, input0.publicKey, input0.blinding, vortex))
    val input1Commitment =
      poseidon4(listOf(input1.amount, input1.publicKey, input1.blinding, vortex))

    val input0Signature = poseidon3(listOf(input0.privateKey, input0Commitment, input0.pathIndex))
    val input1Signature = poseidon3(listOf(input1.privateKey, input1Commitment, input1.pathIndex))

    val input0Nullifier = poseidon3(listOf(input0Commitment, input0.pathIndex, input0Signature))
    val input1Nullifier = poseidon3(listOf(input1Commitment, input1.pathIndex, input1Signature))

    val outputCommitment0 =
      poseidon4(
        listOf(output0.amount.toString(), output0.publicKey, output0.blinding.toString(), vortex)
      )
    val outputCommitment1 =
      poseidon4(
        listOf(output1.amount.toString(), output1.publicKey, output1.blinding.toString(), vortex)
      )

    return buildJsonObject {
        put("vortex", vortex)
        put("root", root)
        put("publicAmount", publicAmount)
        put("inputNullifier0", input0Nullifier)
        put("inputNullifier1", input1Nullifier)
        put("outputCommitment0", outputCommitment0)
        put("outputCommitment1", outputCommitment1)
        put("hashedAccountSecret", "0")
        put("accountSecret", "0")

        put("inPrivateKey0", input0.privateKey)
        put("inAmount0", input0.amount)
        put("inBlinding0", input0.blinding)
        put("inPathIndex0", input0.pathIndex)

        put("inPrivateKey1", input1.privateKey)
        put("inAmount1", input1.amount)
        put("inBlinding1", input1.blinding)
        put("inPathIndex1", input1.pathIndex)

        put("outPublicKey0", output0.publicKey)
        put("outAmount0", output0.amount.toString())
        put("outBlinding0", output0.blinding.toString())

        put("outPublicKey1", output1.publicKey)
        put("outAmount1", output1.amount.toString())
        put("outBlinding1", output1.blinding.toString())

        putJsonArray("merklePath0") {
          merklePath0.forEach { pair -> add(buildJsonArrayOfStrings(pair.first, pair.second)) }
        }
        putJsonArray("merklePath1") {
          merklePath1.forEach { pair -> add(buildJsonArrayOfStrings(pair.first, pair.second)) }
        }
      }
      .toString()
  }

  private fun vortexIdField(): String {
    val cleanId = vortexPoolId.removePrefix("0x")
    val idBigInt = BigInteger.parseString(cleanId, 16)
    return idBigInt.mod(BN254_FIELD_MODULUS).toString()
  }

  private suspend fun ensureGasCoinBalance(account: Account, amount: ULong, gasBudget: ULong) {
    var cursor: String? = null
    var hasNext = true
    val gasBuffer = 1_000_000L
    val required = amount.toLong() + gasBudget.toLong() + gasBuffer

    while (hasNext) {
      val data =
        sui
          .getCoins(
            address = account.address,
            first = 50,
            cursor = cursor,
            type = "0x2::coin::Coin<0x2::sui::SUI>",
          )
          .unwrap()
      val objects = data?.address?.objects
      val nodes = objects?.nodes.orEmpty()

      if (nodes.isNotEmpty()) {
        val gasCoin = nodes.first()
        val balance = parseCoinBalance(gasCoin.contents?.json) ?: 0L
        require(balance >= required) {
          "Gas coin balance too low. Gas coin has $balance MIST, " +
            "needs $required MIST. Consolidate SUI into one coin or fund gas coin."
        }
        return
      }

      val page = objects?.pageInfo
      hasNext = page?.hasNextPage == true
      cursor = page?.endCursor
    }

    throw IllegalStateException("No SUI coins found for gas payment")
  }

  private fun parseCoinBalance(json: Any?): Long? {
    val obj = json as? Map<*, *> ?: return null
    val balanceValue = obj["balance"]
    return when (balanceValue) {
      is String -> balanceValue.toLongOrNull()
      is Number -> balanceValue.toLong()
      else -> null
    }
  }

  private fun extractDigest(
    response: ExecuteTransactionBlockMutation.Data?,
    label: String,
  ): String {
    val exec = response?.executeTransaction
    val digest = exec?.effects?.transaction?.digest
    if (!digest.isNullOrBlank()) {
      return digest
    }
    val errors = exec?.errors?.joinToString("; ")
    val status = exec?.effects?.status?.toString()
    val executionError = exec?.effects?.executionError?.toString()
    val details =
      listOfNotNull(
          errors?.takeIf { it.isNotBlank() }?.let { "errors=$it" },
          status?.let { "status=$it" },
          executionError?.let { "executionError=$it" },
        )
        .joinToString(", ")
    val message =
      if (details.isBlank()) {
        "Transaction failed or no digest returned for $label"
      } else {
        "Transaction failed for $label ($details)"
      }
    throw IllegalArgumentException(message)
  }
}

fun buildJsonArrayOfStrings(vararg args: String) = buildJsonArray { for (arg in args) add(arg) }

fun hexStringToByteArray(s: String): ByteArray {
  require(s.length % 2 == 0) { "Hex string must have an even length" }
  val len = s.length
  val data = ByteArray(len / 2)
  var i = 0
  while (i < len) {
    val high = s[i].digitToInt(16)
    val low = s[i + 1].digitToInt(16)
    data[i / 2] = ((high shl 4) + low).toByte()
    i += 2
  }
  return data
}

data class InputWitness(
  val privateKey: String,
  val publicKey: String,
  val amount: String,
  val blinding: String,
  val pathIndex: String,
) {
  companion object {
    fun fromUtxo(utxo: Utxo): InputWitness {
      return InputWitness(
        privateKey = utxo.keypair.privateKey,
        publicKey = utxo.keypair.publicKey,
        amount = utxo.amount.toString(),
        blinding = utxo.blinding.toString(),
        pathIndex = utxo.index.toString(),
      )
    }
  }
}

data class OutputWitness(val publicKey: String, val amount: BigInteger, val blinding: BigInteger)

data class CommitmentPage(
  val events: List<CommitmentEvent>,
  val nextCursor: String?,
  val hasNext: Boolean,
)

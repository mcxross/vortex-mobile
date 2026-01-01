package xyz.mcxross.vortex.vortex

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.collections.get
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import uniffi.vortex.poseidon1
import uniffi.vortex.poseidon2
import uniffi.vortex.poseidon3
import uniffi.vortex.poseidon4
import xyz.mcxross.vortex.utils.Bcs_

data class VortexKeypair(val privateKey: String) {
  val publicKey: String = poseidon1(privateKey)
  val encryptionKey: String = poseidon2(listOf(privateKey, "1"))
}

data class Utxo(
  val amount: BigInteger,
  val blinding: BigInteger,
  val index: BigInteger,
  val keypair: VortexKeypair,
) {
  fun commitment(vortexId: String): String =
    poseidon4(listOf(amount.toString(), keypair.publicKey, blinding.toString(), vortexId))

  fun signature(commitment: String): String =
    poseidon3(listOf(keypair.privateKey, commitment, index.toString()))

  fun nullifier(commitment: String, signature: String): String =
    poseidon3(listOf(commitment, index.toString(), signature))

  companion object {
    fun randomBlinding(): BigInteger = BigInteger.fromLong(Random.nextLong(0, 1_000_000_000))
  }
}

@Serializable
data class UtxoPayload(
  @SerialName("amount") val amount: String,
  @SerialName("blinding") val blinding: String,
)

object VortexCrypto {
  private val json = Json { ignoreUnknownKeys = true }

  fun encryptUtxoFor(payload: UtxoPayload, encryptionKey: String): ByteArray {
    val plaintext = json.encodeToString(UtxoPayload.serializer(), payload).encodeToByteArray()
    val key = deriveKeyBytes(encryptionKey)
    return xorWithKey(plaintext, key)
  }

  fun decryptUtxo(encrypted: ByteArray, privateKey: String): UtxoPayload? {
    val encryptionKey = poseidon2(listOf(privateKey, "1"))
    val key = deriveKeyBytes(encryptionKey)
    val plaintext = xorWithKey(encrypted, key)
    return runCatching {
        json.decodeFromString(UtxoPayload.serializer(), plaintext.decodeToString())
      }
      .getOrNull()
  }

  private fun deriveKeyBytes(encryptionKey: String): ByteArray {
    return Bcs_.serializeU256(encryptionKey)
  }

  private fun xorWithKey(data: ByteArray, key: ByteArray): ByteArray {
    val out = ByteArray(data.size)
    for (i in data.indices) {
      out[i] = (data[i].toInt() xor key[i % key.size].toInt()).toByte()
    }
    return out
  }
}

data class CommitmentEvent(
  val index: ULong,
  val commitment: String,
  val encryptedOutput: ByteArray,
)

class VortexMerkleTree(
  private val height: Int = MERKLE_TREE_LEVEL,
  private val emptyHashes: List<String> = EMPTY_SUBTREE_HASHES,
) {
  private val leaves: MutableList<String> = mutableListOf()
  private val levels: MutableList<List<String>> = mutableListOf()

  fun bulkInsert(commitments: List<String>) {
    leaves.addAll(commitments)
    rebuild()
  }

  fun insertPair(commitment0: String, commitment1: String) {
    leaves.add(commitment0)
    leaves.add(commitment1)
    rebuild()
  }

  fun root(): String {
    if (leaves.isEmpty()) {
      return emptyHashes[height]
    }
    return levels.lastOrNull()?.firstOrNull() ?: emptyHashes[height]
  }

  fun path(index: Int): List<Pair<String, String>> {
    require(index in leaves.indices) { "Index out of bounds for Merkle tree" }
    val path = mutableListOf<Pair<String, String>>()
    var idx = index
    for (level in 0 until height) {
      val levelNodes = if (level == 0) leaves else levels[level]
      val empty = if (level == 0) emptyHashes[0] else emptyHashes[level]
      val leftIndex = if (idx % 2 == 0) idx else idx - 1
      val rightIndex = leftIndex + 1
      val left = levelNodes.getOrNull(leftIndex) ?: empty
      val right = levelNodes.getOrNull(rightIndex) ?: empty
      path.add(left to right)
      idx /= 2
    }
    return path
  }

  private fun rebuild() {
    levels.clear()
    var current = leaves.toList()
    levels.add(current)
    for (level in 1..height) {
      val next = mutableListOf<String>()
      if (current.isEmpty()) {
        next.add(emptyHashes[level])
      } else {
        var i = 0
        while (i < current.size) {
          val left = current[i]
          val right = current.getOrNull(i + 1) ?: emptyHashes[level - 1]
          next.add(poseidon2(listOf(left, right)))
          i += 2
        }
      }
      levels.add(next)
      current = next
    }
  }

  companion object {
    fun fromEvents(events: List<CommitmentEvent>): VortexMerkleTree {
      val tree = VortexMerkleTree()
      val commitments = events.sortedBy { it.index }.map { it.commitment }
      tree.bulkInsert(commitments)
      return tree
    }
  }
}

@OptIn(ExperimentalEncodingApi::class)
fun parseCommitmentEventJson(json: Any?): CommitmentEvent? {
  val obj = json as? Map<*, *> ?: return null
  val indexStr = obj["index"] as? String ?: return null
  val commitment = obj["commitment"] as? String ?: return null
  val encryptedOutputBase64 = obj["encrypted_output"] as? String ?: return null
  val index = indexStr.toULongOrNull() ?: return null
  val encryptedOutput = Base64.decode(encryptedOutputBase64)
  return CommitmentEvent(index, commitment, encryptedOutput)
}

const val MERKLE_TREE_LEVEL: Int = 26

val EMPTY_SUBTREE_HASHES: List<String> =
  listOf(
    "18688842432741139442778047327644092677418528270738216181718229581494125774932",
    "929670100605127589096201729966801143828059989180770638007278601230757123028",
    "20059153686521406362481271315473498068253845102360114882796737328118528819600",
    "667276972495892769517195136104358636854444397700904910347259067486374491460",
    "12333205860481369973758777121486440301866097422034925170601892818077919669856",
    "13265906118204670164732063746425660672195834675096811019428798251172285860978",
    "3254533810100792365765975246297999341668420141674816325048742255119776645299",
    "18309808253444361227126414342398728022042151803316641228967342967902364963927",
    "12126650299593052178871547753567584772895820192048806970138326036720774331291",
    "9949817351285988369728267498508465715570337443235086859122087250007803517342",
    "11208526958197959509185914785003803401681281543885952782991980697855275912368",
    "59685738145310886711325295148553591612803302297715439999772116453982910402",
    "20837058910394942465479261789141487609029093821244922450759151002393360448717",
    "8209451842087447702442792222326370366485985268583914555249981462794434142285",
    "19651337661238139284113069695072175498780734789512991455990330919229086149402",
    "11527931080332651861006914960138009072130600556413592683110711451245237795573",
    "20764556403192106825184782309105498322242675071639346714780565918367449744227",
    "10818178251908058160377157228631396071771716850372988172358158281935915764080",
    "21598305620835755437985090087223184201582363356396834169567261294737143234327",
    "16481295130402928965223624965091828506529631770925981912487987233811901391354",
    "17911512007742433173433956238979622028159186641781974955249650899638270671335",
    "5186032540459307640178997905000265487821097518169449170073506338735292796958",
    "19685513117592528774434273738957742787082069361009067298107167967352389473358",
    "10912258653908058948673432107359060806004349811796220228800269957283778663923",
    "19880031465088514794850462701773174075421406509504511537647395867323147191667",
    "18344394662872801094289264994998928886741543433797415760903591256277307773470",
    "4023688209857926016730691838838984168964497755397275208674494663143007853450",
    "17055783594241143909439856980092099474877726697157440085377630370122026265082",
    "11977926289934490781035408984815805799047418332367129159688326349739029448709",
    "15234625627661323144444670162795779218620386251655457701229891659668427854091",
    "7411478947588169403968017607782514706815527017510001740123258574686422728877",
    "3160803355012082913337590211745210499441340098978812414661765381488126569348",
  )

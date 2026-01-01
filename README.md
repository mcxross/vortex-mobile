Kotlin Multiplatform client for Vortex on Sui (Android + iOS).

## What It Does

- Deposit: creates a shielded UTXO by generating a ZK proof and submitting a Vortex `transact` call on Sui.
- Private transfer: spends shielded UTXOs, generates a new proof, and sends encrypted outputs to the recipient.
- Registry: resolves and registers encryption keys for recipients.
- Inbox: scans commitment events, decrypts outputs, and keeps local state for pagination.

## Kotlin, Rust, ksui, and BCS

- Rust circuits and helpers live in `composeApp/src/commonMain/rust` and are exposed to Kotlin via UniFFI.
  The generated bindings are used from Kotlin (`uniffi.vortex.*`) for Poseidon hashing and proof generation.
- The Kotlin side builds inputs for the circuit, calls `prove(...)` via the UniFFI bindings, and then
  assembles Sui transactions with the resulting proof and public inputs.
- `ksui` is used for Sui transaction building, signing, execution, event queries, and GraphQL object
  queries. The client uses the PTB builder (`ptb { ... }`) to create the on-chain calls for deposit,
  transfer, registry, and inbox scans, and uses `getObject` for registry resolution.
- BCS is used when serializing data for Move calls. The app uses `xyz.mcxross.bcs.Bcs` for encoding byte
  vectors (for encrypted outputs and proofs) and a minimal custom BCS helper (`Bcs_`) for u256 values.


## Architecture

- `composeApp/src/commonMain/kotlin/xyz/mcxross/vortex/App.kt` hosts the Compose UI and orchestrates all flows.
- `composeApp/src/commonMain/kotlin/xyz/mcxross/vortex/ui` contains UI colors and reusable components.
- `composeApp/src/commonMain/kotlin/xyz/mcxross/vortex/vortex/VortexClient.kt` is the main client for deposit,
  private transfer, registry, and inbox scanning.
- `composeApp/src/commonMain/kotlin/xyz/mcxross/vortex/vortex/VortexTypes.kt` contains keypairs, UTXO types,
  merkle tree, encryption helpers, and event parsing.
- `composeApp/src/commonMain/kotlin/xyz/mcxross/vortex/vortex/VortexStore.kt` provides inbox and registry
  persistence with platform-specific storage.
- `composeApp/src/commonMain/rust` holds the Rust circuits and UniFFI bindings used for Poseidon and proving.
- `composeApp/src/commonMain/composeResources/files` contains the proving/verification keys.
- Package IDs and pool IDs are defined in `composeApp/src/commonMain/kotlin/xyz/mcxross/vortex/utils/Consts.kt`.

## Run

Prereqs:
- JDK 17
- Android Studio and Android SDKs for Android builds
- Xcode for iOS builds
- Rust toolchain (stable) for UniFFI bindings

### Android

From the repo root:
```shell
./gradlew :composeApp:assembleDebug
```

Or run from Android Studio using the `composeApp` configuration.

### iOS

Open `iosApp/iosApp.xcodeproj` in Xcode and run the `iosApp` scheme.

You can also build the framework from Gradle:
```shell
./gradlew :composeApp:embedAndSignAppleFrameworkForXcode
```

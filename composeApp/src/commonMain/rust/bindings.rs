use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use std::str::FromStr;
use num_bigint::BigUint;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_crypto_primitives::snark::SNARK;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use crate::poseidon_opt::{hash1, hash2, hash3, hash4};
use crate::wasm::{ProofOutput, ProofInput};
use crate::circuit::TransactionCircuit;
use crate::constants::MERKLE_TREE_LEVEL;
use crate::merkle_tree::Path;

lazy_static! {
    static ref PROVING_KEY_CACHE: Arc<Mutex<Option<ProvingKey<Bn254>>>> = Arc::new(Mutex::new(None));
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BindingError {
    #[error("Failed to parse field element: {0}")]
    ParseError(String),
    #[error("Failed to deserialize key: {0}")]
    KeyError(String),
    #[error("Failed to generate proof: {0}")]
    ProofError(String),
    #[error("Failed to verify proof: {0}")]
    VerifyError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid input: {0}")]
    InputError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<anyhow::Error> for BindingError {
    fn from(e: anyhow::Error) -> Self {
        BindingError::InternalError(e.to_string())
    }
}

fn parse_fr(s: &str) -> Result<Fr, BindingError> {
    BigUint::from_str(s)
        .map(Fr::from)
        .map_err(|e| BindingError::ParseError(format!("Failed to parse '{}': {}", s, e)))
}

fn fr_to_string(f: &Fr) -> String {
    f.into_bigint().to_string()
}

#[uniffi::export]
pub fn poseidon1(input: String) -> Result<String, BindingError> {
    let fr = parse_fr(&input)?;
    let hash = hash1(&fr);
    Ok(fr_to_string(&hash))
}

#[uniffi::export]
pub fn poseidon2(inputs: Vec<String>) -> Result<String, BindingError> {
    if inputs.len() != 2 {
        return Err(BindingError::InputError("poseidon2 requires 2 inputs".into()));
    }
    let frs: Result<Vec<Fr>, _> = inputs.iter().map(|s| parse_fr(s)).collect();
    let frs = frs?;
    let hash = hash2(&frs[0], &frs[1]);
    Ok(fr_to_string(&hash))
}

#[uniffi::export]
pub fn poseidon3(inputs: Vec<String>) -> Result<String, BindingError> {
    if inputs.len() != 3 {
        return Err(BindingError::InputError("poseidon3 requires 3 inputs".into()));
    }
    let frs: Result<Vec<Fr>, _> = inputs.iter().map(|s| parse_fr(s)).collect();
    let frs = frs?;
    let hash = hash3(&frs[0], &frs[1], &frs[2]);
    Ok(fr_to_string(&hash))
}

#[uniffi::export]
pub fn poseidon4(inputs: Vec<String>) -> Result<String, BindingError> {
    if inputs.len() != 4 {
        return Err(BindingError::InputError("poseidon4 requires 4 inputs".into()));
    }
    let frs: Result<Vec<Fr>, _> = inputs.iter().map(|s| parse_fr(s)).collect();
    let frs = frs?;
    let hash = hash4(&frs[0], &frs[1], &frs[2], &frs[3]);
    Ok(fr_to_string(&hash))
}

#[uniffi::export]
pub fn init_prover_cache(proving_key: Vec<u8>) -> Result<bool, BindingError> {
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&proving_key[..])
        .map_err(|e| BindingError::KeyError(format!("Failed to deserialize proving key: {}", e)))?;

    let mut cache = PROVING_KEY_CACHE.lock().unwrap();
    *cache = Some(pk);
    Ok(true)
}

#[uniffi::export]
pub fn clear_prover_cache() -> bool {
    let mut cache = PROVING_KEY_CACHE.lock().unwrap();
    *cache = None;
    true
}

#[uniffi::export]
pub fn init_logger() -> bool {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("RustCircuit"),
        );
        true
    }
    #[cfg(not(target_os = "android"))]
    {
        // Simple logger for non-android environments (like tests)
         let _ = log::set_boxed_logger(Box::new(SimpleLogger));
         let _ = log::set_max_level(log::LevelFilter::Debug);
         true
    }
}

struct SimpleLogger;
impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}


#[uniffi::export]
pub fn prove(input_json: String, proving_key: Vec<u8>) -> Result<String, BindingError> {

    let cached_pk = {
        let cache = PROVING_KEY_CACHE.lock().unwrap();
        cache.clone()
    };

    let pk = if let Some(pk) = cached_pk {
        pk
    } else {
        ProvingKey::<Bn254>::deserialize_compressed(&proving_key[..])
             .map_err(|e| BindingError::KeyError(format!("Failed to deserialize proving key: {}", e)))?
    };


    let input: ProofInput = serde_json::from_str(&input_json)
        .map_err(|e| BindingError::ParseError(format!("Failed to parse input JSON: {}", e)))?;

    let circuit = create_circuit_from_input(&input)?;

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| BindingError::ProofError(format!("Failed to generate proof: {}", e)))?;

    let public_inputs_field = circuit.get_public_inputs();
    let public_inputs_serialized = circuit
        .get_public_inputs_serialized()
        .map_err(|e| BindingError::SerializationError(format!("Failed to serialize public inputs: {}", e)))?;

     let mut proof_a_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_a_bytes)
        .map_err(|e| BindingError::SerializationError(format!("Failed to serialize proof.a: {}", e)))?;

    let mut proof_b_bytes = Vec::new();
    proof.b.serialize_compressed(&mut proof_b_bytes)
        .map_err(|e| BindingError::SerializationError(format!("Failed to serialize proof.b: {}", e)))?;

    let mut proof_c_bytes = Vec::new();
    proof.c.serialize_compressed(&mut proof_c_bytes)
        .map_err(|e| BindingError::SerializationError(format!("Failed to serialize proof.c: {}", e)))?;

    let mut proof_serialized = Vec::new();
    proof.serialize_compressed(&mut proof_serialized).unwrap();

    let public_inputs: Vec<String> = public_inputs_field
        .iter()
        .map(|input| input.into_bigint().to_string())
        .collect();

    let output = ProofOutput {
        proof_a: proof_a_bytes,
        proof_b: proof_b_bytes,
        proof_c: proof_c_bytes,
        public_inputs,
        proof_serialized_hex: hex::encode(proof_serialized),
        public_inputs_serialized_hex: hex::encode(public_inputs_serialized),
    };

    serde_json::to_string(&output)
        .map_err(|e| BindingError::SerializationError(format!("Failed to serialize output: {}", e)))
}

#[uniffi::export]
pub fn verify(proof_json: String, verifying_key: Vec<u8>) -> Result<bool, BindingError> {
    let proof_output: ProofOutput = serde_json::from_str(&proof_json)
        .map_err(|e| BindingError::ParseError(format!("Failed to parse proof JSON: {}", e)))?;

    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&verifying_key[..])
        .map_err(|e| BindingError::KeyError(format!("Failed to deserialize verifying key: {}", e)))?;

    let pvk = ark_groth16::prepare_verifying_key(&vk);

    let proof_bytes = hex::decode(&proof_output.proof_serialized_hex)
        .map_err(|e| BindingError::ParseError(format!("Failed to decode proof hex: {}", e)))?;

    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
        .map_err(|e| BindingError::ParseError(format!("Failed to deserialize proof: {}", e)))?;

    let public_inputs: Result<Vec<Fr>, _> = proof_output.public_inputs.iter()
        .map(|s| parse_fr(s))
        .collect();
    let public_inputs = public_inputs?;

    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| BindingError::VerifyError(format!("Verify failed: {}", e)))?;

    Ok(is_valid)
}


fn create_circuit_from_input(input: &ProofInput) -> Result<TransactionCircuit, BindingError> {
    let vortex = parse_fr(&input.vortex)?;
    let root = parse_fr(&input.root)?;
    let public_amount = parse_fr(&input.public_amount)?;
    let input_nullifier_0 = parse_fr(&input.input_nullifier_0)?;
    let input_nullifier_1 = parse_fr(&input.input_nullifier_1)?;
    let output_commitment_0 = parse_fr(&input.output_commitment_0)?;
    let output_commitment_1 = parse_fr(&input.output_commitment_1)?;
    let hashed_account_secret = parse_fr(&input.hashed_account_secret)?;
    let account_secret = parse_fr(&input.account_secret)?;

    let in_private_keys = [
        parse_fr(&input.in_private_key_0)?,
        parse_fr(&input.in_private_key_1)?,
    ];
    let in_amounts = [
        parse_fr(&input.in_amount_0)?,
        parse_fr(&input.in_amount_1)?,
    ];
    let in_blindings = [
        parse_fr(&input.in_blinding_0)?,
        parse_fr(&input.in_blinding_1)?,
    ];
    let in_path_indices = [
        parse_fr(&input.in_path_index_0)?,
        parse_fr(&input.in_path_index_1)?,
    ];

    let merkle_paths = [
        parse_merkle_path_binding(&input.merkle_path_0)?,
        parse_merkle_path_binding(&input.merkle_path_1)?,
    ];

    let out_public_keys = [
        parse_fr(&input.out_public_key_0)?,
        parse_fr(&input.out_public_key_1)?,
    ];
    let out_amounts = [
        parse_fr(&input.out_amount_0)?,
        parse_fr(&input.out_amount_1)?,
    ];
    let out_blindings = [
        parse_fr(&input.out_blinding_0)?,
        parse_fr(&input.out_blinding_1)?,
    ];

    TransactionCircuit::new(
        vortex,
        root,
        public_amount,
        input_nullifier_0,
        input_nullifier_1,
        output_commitment_0,
        output_commitment_1,
        hashed_account_secret,
        account_secret,
        in_private_keys,
        in_amounts,
        in_blindings,
        in_path_indices,
        merkle_paths,
        out_public_keys,
        out_amounts,
        out_blindings,
    ).map_err(|e| BindingError::InternalError(e.to_string()))
}

fn parse_merkle_path_binding(path_data: &[[String; 2]]) -> Result<Path<MERKLE_TREE_LEVEL>, BindingError> {
    if path_data.len() != MERKLE_TREE_LEVEL {
        return Err(BindingError::InputError(format!(
            "Invalid Merkle path length: expected {}, got {}",
            MERKLE_TREE_LEVEL,
            path_data.len()
        )));
    }

    let mut path = [(Fr::from(0u64), Fr::from(0u64)); MERKLE_TREE_LEVEL];

    for (i, pair) in path_data.iter().enumerate() {
        let left = parse_fr(&pair[0])?;
        let right = parse_fr(&pair[1])?;
        path[i] = (left, right);
    }

    Ok(Path { path })
}

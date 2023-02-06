use std::result::Result as StdResult;

use eth_light_client_in_ckb_verification::types::core;
use eyre::Result;
use serde::de::Error;
use ssz_rs::prelude::*;

use common::types::Bytes32;
use common::utils::hex_str_to_bytes;

pub type BLSPubKey = Vector<u8, 48>;
pub type SignatureBytes = Vector<u8, 96>;
pub type Address = Vector<u8, 20>;
pub type LogsBloom = Vector<u8, 256>;
pub type Transaction = List<u8, 1073741824>;

pub type BeaconBlock = eth2_types::BeaconBlock<eth2_types::MainnetEthSpec>;
pub type ExecutionPayload = eth2_types::ExecutionPayload<eth2_types::MainnetEthSpec>;

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct ProposerSlashing {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct SignedBeaconBlockHeader {
    message: BeaconBlockHeader,
    #[serde(deserialize_with = "signature_deserialize")]
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct BeaconBlockHeader {
    #[serde(deserialize_with = "u64_deserialize")]
    slot: u64,
    #[serde(deserialize_with = "u64_deserialize")]
    proposer_index: u64,
    #[serde(deserialize_with = "bytes32_deserialize")]
    parent_root: Bytes32,
    #[serde(deserialize_with = "bytes32_deserialize")]
    state_root: Bytes32,
    #[serde(deserialize_with = "bytes32_deserialize")]
    body_root: Bytes32,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct AttesterSlashing {
    attestation_1: IndexedAttestation,
    attestation_2: IndexedAttestation,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct IndexedAttestation {
    #[serde(deserialize_with = "attesting_indices_deserialize")]
    attesting_indices: List<u64, 2048>,
    data: AttestationData,
    #[serde(deserialize_with = "signature_deserialize")]
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct Attestation {
    aggregation_bits: Bitlist<2048>,
    data: AttestationData,
    #[serde(deserialize_with = "signature_deserialize")]
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct AttestationData {
    #[serde(deserialize_with = "u64_deserialize")]
    slot: u64,
    #[serde(deserialize_with = "u64_deserialize")]
    index: u64,
    #[serde(deserialize_with = "bytes32_deserialize")]
    beacon_block_root: Bytes32,
    source: Checkpoint,
    target: Checkpoint,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct Checkpoint {
    #[serde(deserialize_with = "u64_deserialize")]
    epoch: u64,
    #[serde(deserialize_with = "bytes32_deserialize")]
    root: Bytes32,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct SignedVoluntaryExit {
    message: VoluntaryExit,
    #[serde(deserialize_with = "signature_deserialize")]
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct VoluntaryExit {
    #[serde(deserialize_with = "u64_deserialize")]
    epoch: u64,
    #[serde(deserialize_with = "u64_deserialize")]
    validator_index: u64,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
struct Deposit {
    #[serde(deserialize_with = "bytes_vector_deserialize")]
    proof: Vector<Bytes32, 33>,
    data: DepositData,
}

#[derive(serde::Deserialize, Default, Debug, SimpleSerialize, Clone)]
struct DepositData {
    #[serde(deserialize_with = "pubkey_deserialize")]
    pubkey: BLSPubKey,
    #[serde(deserialize_with = "bytes32_deserialize")]
    withdrawal_credentials: Bytes32,
    #[serde(deserialize_with = "u64_deserialize")]
    amount: u64,
    #[serde(deserialize_with = "signature_deserialize")]
    signature: SignatureBytes,
}

#[derive(serde::Deserialize, Debug, Default, SimpleSerialize, Clone)]
pub struct Eth1Data {
    #[serde(deserialize_with = "bytes32_deserialize")]
    deposit_root: Bytes32,
    #[serde(deserialize_with = "u64_deserialize")]
    deposit_count: u64,
    #[serde(deserialize_with = "bytes32_deserialize")]
    block_hash: Bytes32,
}

#[derive(serde::Deserialize, Debug)]
pub struct Bootstrap {
    #[serde(deserialize_with = "header_deserialize")]
    pub header: Header,
    pub current_sync_committee: SyncCommittee,
    #[serde(deserialize_with = "branch_deserialize")]
    pub current_sync_committee_branch: Vec<Bytes32>,
}

#[derive(serde::Deserialize, Debug, Clone, Default)]
pub struct Update {
    #[serde(deserialize_with = "header_deserialize")]
    pub attested_header: Header,
    pub next_sync_committee: SyncCommittee,
    #[serde(deserialize_with = "branch_deserialize")]
    pub next_sync_committee_branch: Vec<Bytes32>,
    #[serde(deserialize_with = "header_deserialize")]
    pub finalized_header: Header,
    #[serde(deserialize_with = "branch_deserialize")]
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate,
    #[serde(deserialize_with = "u64_deserialize")]
    pub signature_slot: u64,
}

#[derive(Default, SimpleSerialize)]
struct InnerUpdate {
    pub attested_header: Header,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: List<Bytes32, 512>,
    pub finalized_header: Header,
    pub finality_branch: List<Bytes32, 512>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

impl Update {
    pub fn from_finality_update(
        update: FinalityUpdate,
        next_sync_committee: SyncCommittee,
        next_sync_committee_branch: Vec<Bytes32>,
    ) -> Self {
        Self {
            attested_header: update.attested_header,
            finalized_header: update.finalized_header,
            finality_branch: update.finality_branch,
            sync_aggregate: update.sync_aggregate,
            signature_slot: update.signature_slot,
            next_sync_committee,
            next_sync_committee_branch,
        }
    }

    pub fn from_finalized_header(header: Header) -> Self {
        Self {
            finalized_header: header,
            ..Default::default()
        }
    }

    pub fn is_finalized_empty(&self) -> bool {
        let header = &self.finalized_header;
        header.slot > 0
            && header.proposer_index == 0
            && header.parent_root == Default::default()
            && header.state_root == Default::default()
            && header.body_root == Default::default()
    }

    fn from_inner(inner: InnerUpdate) -> Self {
        let InnerUpdate {
            attested_header,
            finalized_header,
            finality_branch,
            next_sync_committee,
            next_sync_committee_branch,
            sync_aggregate,
            signature_slot,
        } = inner;
        Update {
            attested_header,
            finalized_header,
            finality_branch: finality_branch.to_vec(),
            next_sync_committee,
            next_sync_committee_branch: next_sync_committee_branch.to_vec(),
            sync_aggregate,
            signature_slot,
        }
    }

    pub fn from_slice(bytes: &[u8]) -> StdResult<Self, DeserializeError> {
        let inner = InnerUpdate::deserialize(bytes)?;
        Ok(Self::from_inner(inner))
    }

    pub fn into_bytes(self) -> StdResult<Vec<u8>, SerializeError> {
        let Update {
            attested_header,
            finalized_header,
            finality_branch,
            next_sync_committee,
            next_sync_committee_branch,
            sync_aggregate,
            signature_slot,
        } = self;
        let inner = InnerUpdate {
            attested_header,
            finalized_header,
            finality_branch: List::from_iter(finality_branch.into_iter()),
            next_sync_committee,
            next_sync_committee_branch: List::from_iter(next_sync_committee_branch.into_iter()),
            sync_aggregate,
            signature_slot,
        };
        let mut bytes = Vec::new();
        inner.serialize(&mut bytes)?;
        Ok(bytes)
    }
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct FinalityUpdate {
    #[serde(deserialize_with = "header_deserialize")]
    pub attested_header: Header,
    #[serde(deserialize_with = "header_deserialize")]
    pub finalized_header: Header,
    #[serde(deserialize_with = "branch_deserialize")]
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate,
    #[serde(deserialize_with = "u64_deserialize")]
    pub signature_slot: u64,
}

#[derive(serde::Deserialize, Debug)]
pub struct OptimisticUpdate {
    #[serde(deserialize_with = "header_deserialize")]
    pub attested_header: Header,
    pub sync_aggregate: SyncAggregate,
    #[serde(deserialize_with = "u64_deserialize")]
    pub signature_slot: u64,
}

#[derive(serde::Deserialize, Debug, Clone, Default, SimpleSerialize)]
pub struct Header {
    #[serde(deserialize_with = "u64_deserialize")]
    pub slot: u64,
    #[serde(deserialize_with = "u64_deserialize")]
    pub proposer_index: u64,
    #[serde(deserialize_with = "bytes32_deserialize")]
    pub parent_root: Bytes32,
    #[serde(deserialize_with = "bytes32_deserialize")]
    pub state_root: Bytes32,
    #[serde(deserialize_with = "bytes32_deserialize")]
    pub body_root: Bytes32,
}

#[derive(Debug, Clone, Default, SimpleSerialize, serde::Deserialize)]
pub struct SyncCommittee {
    #[serde(deserialize_with = "pubkeys_deserialize")]
    pub pubkeys: Vector<BLSPubKey, 512>,
    #[serde(deserialize_with = "pubkey_deserialize")]
    pub aggregate_pubkey: BLSPubKey,
}

#[derive(serde::Deserialize, Debug, Clone, Default, SimpleSerialize)]
pub struct SyncAggregate {
    pub sync_committee_bits: Bitvector<512>,
    #[serde(deserialize_with = "signature_deserialize")]
    pub sync_committee_signature: SignatureBytes,
}

pub struct GenericUpdate {
    pub attested_header: Header,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
    pub next_sync_committee: Option<SyncCommittee>,
    pub next_sync_committee_branch: Option<Vec<Bytes32>>,
    pub finalized_header: Option<Header>,
    pub finality_branch: Option<Vec<Bytes32>>,
}

impl From<&Update> for GenericUpdate {
    fn from(update: &Update) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: Some(update.next_sync_committee.clone()),
            next_sync_committee_branch: Some(update.next_sync_committee_branch.clone()),
            finalized_header: Some(update.finalized_header.clone()),
            finality_branch: Some(update.finality_branch.clone()),
        }
    }
}

impl From<&FinalityUpdate> for GenericUpdate {
    fn from(update: &FinalityUpdate) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: Some(update.finalized_header.clone()),
            finality_branch: Some(update.finality_branch.clone()),
        }
    }
}

impl From<&OptimisticUpdate> for GenericUpdate {
    fn from(update: &OptimisticUpdate) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: None,
            finality_branch: None,
        }
    }
}

impl From<&Header> for core::Header {
    fn from(input: &Header) -> Self {
        Self {
            slot: input.slot,
            proposer_index: input.proposer_index,
            parent_root: core::Hash::from_slice(&input.parent_root),
            state_root: core::Hash::from_slice(&input.state_root),
            body_root: core::Hash::from_slice(&input.body_root),
        }
    }
}

fn pubkey_deserialize<'de, D>(deserializer: D) -> Result<BLSPubKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let key: String = serde::Deserialize::deserialize(deserializer)?;
    let key_bytes = hex_str_to_bytes(&key).map_err(D::Error::custom)?;
    Ok(Vector::from_iter(key_bytes))
}

fn pubkeys_deserialize<'de, D>(deserializer: D) -> Result<Vector<BLSPubKey, 512>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let keys: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    keys.iter()
        .map(|key| {
            let key_bytes = hex_str_to_bytes(key)?;
            Ok(Vector::from_iter(key_bytes))
        })
        .collect::<Result<Vector<BLSPubKey, 512>>>()
        .map_err(D::Error::custom)
}

fn bytes_vector_deserialize<'de, D>(deserializer: D) -> Result<Vector<Bytes32, 33>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let elems: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    elems
        .iter()
        .map(|elem| {
            let elem_bytes = hex_str_to_bytes(elem)?;
            Ok(Vector::from_iter(elem_bytes))
        })
        .collect::<Result<Vector<Bytes32, 33>>>()
        .map_err(D::Error::custom)
}

fn signature_deserialize<'de, D>(deserializer: D) -> Result<SignatureBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let sig: String = serde::Deserialize::deserialize(deserializer)?;
    let sig_bytes = hex_str_to_bytes(&sig).map_err(D::Error::custom)?;
    Ok(Vector::from_iter(sig_bytes))
}

fn branch_deserialize<'de, D>(deserializer: D) -> Result<Vec<Bytes32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let branch: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    branch
        .iter()
        .map(|elem| {
            let elem_bytes = hex_str_to_bytes(elem)?;
            Ok(Vector::from_iter(elem_bytes))
        })
        .collect::<Result<_>>()
        .map_err(D::Error::custom)
}

fn u64_deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val: String = serde::Deserialize::deserialize(deserializer)?;
    Ok(val.parse().unwrap())
}

fn bytes32_deserialize<'de, D>(deserializer: D) -> Result<Bytes32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: String = serde::Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(bytes.strip_prefix("0x").unwrap()).unwrap();
    Ok(bytes.to_vec().try_into().unwrap())
}

fn attesting_indices_deserialize<'de, D>(deserializer: D) -> Result<List<u64, 2048>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let attesting_indices: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    let attesting_indices = attesting_indices
        .iter()
        .map(|i| i.parse().unwrap())
        .collect::<List<u64, 2048>>();

    Ok(attesting_indices)
}

fn header_deserialize<'de, D>(deserializer: D) -> Result<Header, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let header: LightClientHeader = serde::Deserialize::deserialize(deserializer)?;

    Ok(match header {
        LightClientHeader::Unwrapped(header) => header,
        LightClientHeader::Wrapped(header) => header.beacon,
    })
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum LightClientHeader {
    Unwrapped(Header),
    Wrapped(Beacon),
}

#[derive(serde::Deserialize)]
struct Beacon {
    beacon: Header,
}

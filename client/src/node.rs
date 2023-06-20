use ckb_jsonrpc_types::Transaction as CkbTransaction;
use consensus::rpc::ConsensusRpc;
use forcerelay::{rpc::RpcClient, CachedBeaconBlockMainnet};
use futures::TryFutureExt;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ethers::prelude::{Address, U256};
use ethers::types::{Filter, Log, Transaction, TransactionReceipt, H256};
use eyre::{eyre, Result};

use common::errors::BlockNotFoundError;
use common::types::BlockTag;
use config::Config;
use consensus::rpc::nimbus_rpc::NimbusRpc;
use consensus::types::{ExecutionPayload, Header};
use consensus::ConsensusClient;
use execution::evm::Evm;
use execution::rpc::{http_rpc::HttpRpc, ExecutionRpc};
use execution::types::{CallOpts, ExecutionBlock};
use execution::ExecutionClient;
use forcerelay::forcerelay::ForcerelayClient;
use log::info;

use crate::errors::NodeError;

const HISTORY_SIZE: usize = 64;
const CACHED_RECEIPTS_SIZE: usize = 512;
const CACHED_BLOCK_SIZE: usize = 64;

pub struct Node {
    pub consensus: ConsensusClient<NimbusRpc>,
    pub execution: Arc<ExecutionClient<HttpRpc>>,
    pub config: Arc<Config>,
    payloads: BTreeMap<u64, ExecutionPayload>,
    finalized_payloads: BTreeMap<u64, ExecutionPayload>,
    block_number_slots: BTreeMap<u64, u64>,
    cached_block_receipts: BTreeMap<u64, Vec<TransactionReceipt>>,
    cached_beacon_blocks: BTreeMap<u64, CachedBeaconBlockMainnet>,
    forcerelay: ForcerelayClient<RpcClient>,
}

impl Node {
    pub fn new(config: Arc<Config>) -> Result<Self, NodeError> {
        let consensus_rpc = &config.consensus_rpc;
        let checkpoint_hash = &config.checkpoint;
        let execution_rpc = &config.execution_rpc;
        let ckb_rpc = &config.ckb_rpc;
        let contract_typeargs = &config.lightclient_contract_typeargs;
        let client_type_args = &config.lightclient_client_type_args;
        let binary_typeargs = &config.lightclient_binary_typeargs;

        let consensus = ConsensusClient::new(consensus_rpc, checkpoint_hash, config.clone())
            .map_err(NodeError::ConsensusClientCreationError)?;
        let execution = Arc::new(
            ExecutionClient::new(execution_rpc).map_err(NodeError::ExecutionClientCreationError)?,
        );

        let rpc = RpcClient::new(ckb_rpc, ckb_rpc);
        let forcerelay = ForcerelayClient::new(
            rpc,
            contract_typeargs,
            &client_type_args.type_id,
            client_type_args.cells_count,
            binary_typeargs,
        );

        Ok(Node {
            consensus,
            execution,
            config,
            payloads: BTreeMap::new(),
            finalized_payloads: BTreeMap::new(),
            block_number_slots: BTreeMap::new(),
            cached_block_receipts: BTreeMap::new(),
            cached_beacon_blocks: BTreeMap::new(),
            forcerelay,
        })
    }

    pub async fn print_status_log(&self, onchain_log: Option<String>) -> Result<(), NodeError> {
        let onchain_log = match onchain_log {
            Some(log) => log,
            None => {
                let (client, _) = self
                    .forcerelay
                    .onchain_client()
                    .map_err(NodeError::ForcerelayError)
                    .await?;
                client.to_string()
            }
        };
        let mut log = format!("[STATUS] onchain client: {onchain_log}, native client: ");
        let slot_range = self
            .consensus
            .storage_slot_range()
            .map_err(NodeError::ConsensusSyncError)?;
        if let (Some(base_slot), Some(tip_slot)) = slot_range {
            log += &format!("[{base_slot}, {tip_slot}]");
        } else {
            log += "None";
        }
        info!("{log}");
        Ok(())
    }

    pub async fn sync(&mut self) -> Result<(), NodeError> {
        let (client, _) = self
            .forcerelay
            .onchain_client()
            .await
            .map_err(NodeError::ForcerelayError)?;
        self.print_status_log(Some(client.to_string())).await?;
        self.consensus
            .sync(client.minimal_slot)
            .await
            .map_err(NodeError::ConsensusSyncError)?;
        self.forcerelay
            .update_assembler_celldep()
            .await
            .map_err(NodeError::ForcerelayError)?;
        self.update_block_number_slots(client.minimal_slot).await?;
        self.update_block_number_slots(client.maximal_slot).await?;
        self.update_payloads().await
    }

    pub async fn advance(&mut self) -> Result<(), NodeError> {
        let (client, _) = self
            .forcerelay
            .onchain_client()
            .await
            .map_err(NodeError::ForcerelayError)?;
        let new_finality = self
            .consensus
            .advance()
            .await
            .map_err(NodeError::ConsensusAdvanceError)?;
        if new_finality {
            self.print_status_log(Some(client.to_string())).await?;
        }
        if let Some((_, last_maximal_slot)) = self.block_number_slots.last_key_value() {
            for slot in (*last_maximal_slot + 1)..=client.maximal_slot {
                if let Some(block_number) = self.update_block_number_slots(slot).await? {
                    self.cache_block_receipts(block_number).await?;
                }
                self.cache_beacon_block(slot).await?;
            }
        }
        self.forcerelay
            .update_assembler_celldep()
            .await
            .map_err(NodeError::ForcerelayError)?;
        self.update_payloads().await
    }

    pub fn duration_until_next_update(&self) -> Duration {
        self.consensus
            .duration_until_next_update()
            .to_std()
            .unwrap()
    }

    async fn update_block_number_slots(&mut self, slot: u64) -> Result<Option<u64>, NodeError> {
        if let Some(block_number) = self.block_number_slots.get(&slot) {
            Ok(Some(*block_number))
        } else {
            let payload = self
                .consensus
                .get_execution_payload(&Some(slot), false)
                .await
                .map_err(NodeError::ConsensusPayloadError)?;
            if let Some(payload) = payload {
                self.block_number_slots.insert(payload.block_number(), slot);
                Ok(Some(payload.block_number()))
            } else {
                Ok(None)
            }
        }
    }

    async fn cache_block_receipts(&mut self, block_number: u64) -> Result<(), NodeError> {
        if self.cached_block_receipts.contains_key(&block_number) {
            return Ok(());
        }
        if self.cached_block_receipts.len() >= CACHED_RECEIPTS_SIZE {
            self.cached_block_receipts.pop_first();
        }
        let receipts = self
            .execution
            .rpc
            .get_block_receipts(block_number)
            .await
            .map_err(NodeError::ForcerelayError)?;
        self.cached_block_receipts.insert(block_number, receipts);
        Ok(())
    }

    async fn cache_beacon_block(&mut self, slot: u64) -> Result<(), NodeError> {
        if self.cached_beacon_blocks.contains_key(&slot) {
            return Ok(());
        }
        let block = self
            .consensus
            .rpc
            .get_block_ssz(slot)
            .await
            .map_err(NodeError::ForcerelayError)?;
        if let Some(block) = block {
            if self.cached_beacon_blocks.len() >= CACHED_BLOCK_SIZE {
                self.cached_beacon_blocks.pop_first();
            }
            self.cached_beacon_blocks.insert(slot, block.into());
        }
        Ok(())
    }

    async fn get_slot_by_block_number(&mut self, block_number: u64) -> Result<u64, NodeError> {
        if let Some(slot) = self.block_number_slots.get(&block_number) {
            Ok(*slot)
        } else {
            if self.block_number_slots.is_empty() {
                return Err(NodeError::ForcerelayError(eyre!(
                    "cannot find beacon slot by block_number {block_number}"
                )));
            }
            let ((minimal_block_number, minimal_slot), (maximal_block_number, _)) = (
                self.block_number_slots.first_key_value().unwrap(),
                self.block_number_slots.last_key_value().unwrap(),
            );
            if block_number < *minimal_block_number || block_number > *maximal_block_number {
                return Err(NodeError::BlockNumberToSlotError(
                    block_number,
                    *minimal_block_number,
                    *maximal_block_number,
                ));
            }
            let mut try_block_number = *minimal_block_number;
            let mut try_slot = *minimal_slot;
            while block_number > try_block_number {
                try_slot += block_number - try_block_number;
                loop {
                    if let Some(value) = self.update_block_number_slots(try_slot).await? {
                        try_block_number = value;
                        break;
                    } else {
                        try_slot += 1;
                    }
                }
            }
            Ok(try_slot)
        }
    }

    async fn update_payloads(&mut self) -> Result<(), NodeError> {
        let latest_header = self.consensus.get_header();
        let latest_payload = self
            .consensus
            .get_execution_payload(&Some(latest_header.slot), true)
            .await
            .map_err(NodeError::ConsensusPayloadError)?
            .expect("latest execution payload");

        let finalized_header = self.consensus.get_finalized_header();
        let finalized_payload = self
            .consensus
            .get_execution_payload(&Some(finalized_header.slot), true)
            .await
            .map_err(NodeError::ConsensusPayloadError)?
            .expect("finalized execution payload");

        self.payloads
            .insert(latest_payload.block_number(), latest_payload);
        self.payloads
            .insert(finalized_payload.block_number(), finalized_payload.clone());
        self.finalized_payloads
            .insert(finalized_payload.block_number(), finalized_payload);

        while self.payloads.len() > HISTORY_SIZE {
            self.payloads.pop_first();
        }

        // only save one finalized block per epoch
        // finality updates only occur on epoch boundaries
        while self.finalized_payloads.len() > usize::max(HISTORY_SIZE / 32, 1) {
            self.finalized_payloads.pop_first();
        }

        Ok(())
    }

    pub async fn call(&self, opts: &CallOpts, block: BlockTag) -> Result<Vec<u8>, NodeError> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let mut evm = Evm::new(
            self.execution.clone(),
            payload,
            &self.payloads,
            self.chain_id(),
        );
        evm.call(opts).await.map_err(NodeError::ExecutionError)
    }

    pub async fn estimate_gas(&self, opts: &CallOpts) -> Result<u64, NodeError> {
        self.check_head_age()?;

        let payload = self.get_payload(BlockTag::Latest)?;
        let mut evm = Evm::new(
            self.execution.clone(),
            payload,
            &self.payloads,
            self.chain_id(),
        );
        evm.estimate_gas(opts)
            .await
            .map_err(NodeError::ExecutionError)
    }

    pub async fn get_balance(&self, address: &Address, block: BlockTag) -> Result<U256> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let account = self.execution.get_account(address, None, payload).await?;
        Ok(account.balance)
    }

    pub async fn get_nonce(&self, address: &Address, block: BlockTag) -> Result<u64> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let account = self.execution.get_account(address, None, payload).await?;
        Ok(account.nonce)
    }

    pub fn get_block_transaction_count_by_hash(&self, hash: &Vec<u8>) -> Result<u64> {
        let payload = self.get_payload_by_hash(hash)?;
        let transaction_count = payload.1.transactions().len();

        Ok(transaction_count as u64)
    }

    pub fn get_block_transaction_count_by_number(&self, block: BlockTag) -> Result<u64> {
        let payload = self.get_payload(block)?;
        let transaction_count = payload.transactions().len();

        Ok(transaction_count as u64)
    }

    pub async fn get_code(&self, address: &Address, block: BlockTag) -> Result<Vec<u8>> {
        self.check_blocktag_age(&block)?;

        let payload = self.get_payload(block)?;
        let account = self.execution.get_account(address, None, payload).await?;
        Ok(account.code)
    }

    pub async fn get_storage_at(
        &self,
        address: &Address,
        slot: H256,
        block: BlockTag,
    ) -> Result<U256> {
        self.check_head_age()?;

        let payload = self.get_payload(block)?;
        let account = self
            .execution
            .get_account(address, Some(&[slot]), payload)
            .await?;

        let value = account.slots.get(&slot);
        match value {
            Some(value) => Ok(*value),
            None => Err(eyre!("slot not found")),
        }
    }

    pub async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<H256> {
        self.execution.send_raw_transaction(bytes).await
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &H256,
    ) -> Result<Option<TransactionReceipt>> {
        self.execution
            .get_transaction_receipt(tx_hash, &self.payloads)
            .await
    }

    pub async fn get_transaction_by_hash(&self, tx_hash: &H256) -> Result<Option<Transaction>> {
        self.execution
            .get_transaction(tx_hash, &self.payloads)
            .await
    }

    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        hash: &Vec<u8>,
        index: usize,
    ) -> Result<Option<Transaction>> {
        let payload = self.get_payload_by_hash(hash)?;

        self.execution
            .get_transaction_by_block_hash_and_index(payload.1, index)
            .await
    }

    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        self.execution.get_logs(filter, &self.payloads).await
    }

    // assumes tip of 1 gwei to prevent having to prove out every tx in the block
    pub fn get_gas_price(&self) -> Result<U256> {
        self.check_head_age()?;

        let payload = self.get_payload(BlockTag::Latest)?;
        let base_fee = {
            let mut base_fee = [0u8; 32];
            payload.base_fee_per_gas().to_little_endian(&mut base_fee);
            U256::from_little_endian(&base_fee)
        };
        let tip = U256::from(10_u64.pow(9));
        Ok(base_fee + tip)
    }

    // assumes tip of 1 gwei to prevent having to prove out every tx in the block
    pub fn get_priority_fee(&self) -> Result<U256> {
        let tip = U256::from(10_u64.pow(9));
        Ok(tip)
    }

    pub fn get_block_number(&self) -> Result<u64> {
        self.check_head_age()?;

        let payload = self.get_payload(BlockTag::Latest)?;
        Ok(payload.block_number())
    }

    pub async fn get_block_by_number(
        &self,
        block: BlockTag,
        full_tx: bool,
    ) -> Result<Option<ExecutionBlock>> {
        self.check_blocktag_age(&block)?;

        match self.get_payload(block) {
            Ok(payload) => self.execution.get_block(payload, full_tx).await.map(Some),
            Err(_) => Ok(None),
        }
    }

    pub async fn get_block_by_hash(
        &self,
        hash: &Vec<u8>,
        full_tx: bool,
    ) -> Result<Option<ExecutionBlock>> {
        let payload = self.get_payload_by_hash(hash);

        match payload {
            Ok(payload) => self.execution.get_block(payload.1, full_tx).await.map(Some),
            Err(_) => Ok(None),
        }
    }

    // assemble ckb transaction by ethereum hash which refers to the IBC transaction
    pub async fn get_ckb_transaction_by_hash(
        &mut self,
        tx_hash: &H256,
    ) -> Result<Option<CkbTransaction>> {
        let eth_transaction = match self.execution.rpc.get_transaction(tx_hash).await? {
            Some(tx) => tx,
            None => return Ok(None),
        };
        let mut slot = 0;
        let mut block_number = 0;
        if let Some(number) = eth_transaction.block_number {
            block_number = number.as_u64();
            slot = self.get_slot_by_block_number(block_number).await?;
            self.cache_block_receipts(block_number).await?;
            self.cache_beacon_block(slot).await?;
        }
        if slot > 0 && block_number > 0 {
            let (client, client_celldep) = self
                .forcerelay
                .check_onchain_client_alignment(&self.consensus)
                .await?;
            if slot < client.minimal_slot || slot > client.maximal_slot {
                return Err(eyre::eyre!(
                    "beacon slot {slot} is out of range [{}, {}]",
                    client.minimal_slot,
                    client.maximal_slot
                ));
            }
            let block = match self.cached_beacon_blocks.get(&slot) {
                Some(block) => block,
                None => return Err(eyre!("beacon slot {slot} forked or skipped")),
            };
            let receipts = self
                .cached_block_receipts
                .get(&block_number)
                .expect("cache receipts");
            let ckb_transaction = self
                .forcerelay
                .assemble_tx(
                    client,
                    &client_celldep,
                    &self.consensus,
                    block,
                    &eth_transaction,
                    receipts,
                )
                .await?;
            return Ok(Some(ckb_transaction.data().into()));
        }
        Ok(None)
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain.chain_id
    }

    pub fn get_header(&self) -> Result<Header> {
        self.check_head_age()?;
        Ok(self.consensus.get_header().clone())
    }

    pub fn get_coinbase(&self) -> Result<Address> {
        self.check_head_age()?;
        let payload = self.get_payload(BlockTag::Latest)?;
        let coinbase_address = Address::from_slice(payload.fee_recipient().as_bytes());
        Ok(coinbase_address)
    }

    pub fn get_last_checkpoint(&self) -> Option<Vec<u8>> {
        self.consensus.last_checkpoint.clone()
    }

    fn get_payload(&self, block: BlockTag) -> Result<&ExecutionPayload, BlockNotFoundError> {
        match block {
            BlockTag::Latest => {
                let payload = self.payloads.last_key_value();
                Ok(payload.ok_or(BlockNotFoundError::new(BlockTag::Latest))?.1)
            }
            BlockTag::Finalized => {
                let payload = self.finalized_payloads.last_key_value();
                Ok(payload
                    .ok_or(BlockNotFoundError::new(BlockTag::Finalized))?
                    .1)
            }
            BlockTag::Number(num) => {
                let payload = self.payloads.get(&num);
                payload.ok_or(BlockNotFoundError::new(BlockTag::Number(num)))
            }
        }
    }

    fn get_payload_by_hash(&self, hash: &Vec<u8>) -> Result<(&u64, &ExecutionPayload)> {
        let payloads = self
            .payloads
            .iter()
            .filter(|entry| entry.1.block_hash().into_root().as_bytes() == hash)
            .collect::<Vec<(&u64, &ExecutionPayload)>>();

        payloads
            .get(0)
            .cloned()
            .ok_or(eyre!("Block not found by hash"))
    }

    fn check_head_age(&self) -> Result<(), NodeError> {
        let synced_slot = self.consensus.get_header().slot;
        let expected_slot = self.consensus.expected_current_slot();
        let slot_delay = expected_slot - synced_slot;

        if slot_delay > 10 {
            return Err(NodeError::OutOfSync(slot_delay));
        }

        Ok(())
    }

    fn check_blocktag_age(&self, block: &BlockTag) -> Result<(), NodeError> {
        match block {
            BlockTag::Latest => self.check_head_age(),
            BlockTag::Finalized => Ok(()),
            BlockTag::Number(_) => Ok(()),
        }
    }
}

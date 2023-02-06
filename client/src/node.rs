use ckb_jsonrpc_types::Transaction as CkbTransaction;
use ethers::utils::keccak256;
use futures::future::join_all;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use ethers::prelude::{Address, U256};
use ethers::types::{Filter, Log, Transaction, TransactionReceipt, H256};
use eyre::{eyre, Result};

use common::errors::BlockNotFoundError;
use common::types::BlockTag;
use config::Config;
use consensus::rpc::{nimbus_rpc::NimbusRpc, ConsensusRpc};
use consensus::types::{ExecutionPayload, Header};
use consensus::ConsensusClient;
use execution::evm::Evm;
use execution::rpc::{http_rpc::HttpRpc, ExecutionRpc};
use execution::types::{CallOpts, ExecutionBlock};
use execution::ExecutionClient;
use forcerelay::forcerelay::ForcerelayClient;

use crate::errors::NodeError;

pub struct Node {
    pub consensus: ConsensusClient<NimbusRpc>,
    pub execution: Arc<ExecutionClient<HttpRpc>>,
    pub config: Arc<Config>,
    payloads: BTreeMap<u64, ExecutionPayload>,
    finalized_payloads: BTreeMap<u64, ExecutionPayload>,
    pub history_size: usize,
    block_number_slots: HashMap<u64, u64>,
    forcerelay: ForcerelayClient,
}

impl Node {
    pub fn new(config: Arc<Config>) -> Result<Self, NodeError> {
        let consensus_rpc = &config.consensus_rpc;
        let checkpoint_hash = &config.checkpoint;
        let execution_rpc = &config.execution_rpc;
        let ckb_rpc = &config.ckb_rpc;
        let contract_typeargs = &config.lightclient_contract_typeargs;
        let binary_typeargs = &config.lightclient_binary_typeargs;
        let client_id = &config.ckb_ibc_client_id;

        let consensus = ConsensusClient::new(consensus_rpc, checkpoint_hash, config.clone())
            .map_err(NodeError::ConsensusClientCreationError)?;
        let execution = Arc::new(
            ExecutionClient::new(execution_rpc).map_err(NodeError::ExecutionClientCreationError)?,
        );

        let payloads = BTreeMap::new();
        let finalized_payloads = BTreeMap::new();
        let block_number_slots = HashMap::new();
        let forcerelay =
            ForcerelayClient::new(ckb_rpc, contract_typeargs, binary_typeargs, client_id);

        Ok(Node {
            consensus,
            execution,
            config,
            payloads,
            finalized_payloads,
            history_size: 64,
            block_number_slots,
            forcerelay,
        })
    }

    pub async fn sync(&mut self) -> Result<(), NodeError> {
        let client = self
            .forcerelay
            .onchain_client()
            .await
            .map_err(NodeError::ConsensusSyncError)?;
        self.consensus
            .sync(client.minimal_slot)
            .await
            .map_err(NodeError::ConsensusSyncError)?;
        self.update_number_slots().await?;
        self.update_payloads().await
    }

    pub async fn advance(&mut self) -> Result<(), NodeError> {
        self.consensus
            .advance()
            .await
            .map_err(NodeError::ConsensusAdvanceError)?;
        self.update_number_slots().await?;
        self.update_payloads().await
    }

    pub fn duration_until_next_update(&self) -> Duration {
        self.consensus
            .duration_until_next_update()
            .to_std()
            .unwrap()
    }

    async fn update_number_slots(&mut self) -> Result<(), NodeError> {
        let finalized_header = self.consensus.get_finalized_header();
        let finalized_payload = self
            .consensus
            .get_execution_payload(&Some(finalized_header.slot))
            .await
            .map_err(NodeError::ConsensusPayloadError)?;

        self.block_number_slots
            .insert(finalized_payload.block_number, finalized_header.slot);
        Ok(())
    }

    async fn update_payloads(&mut self) -> Result<(), NodeError> {
        let latest_header = self.consensus.get_header();
        let latest_payload = self
            .consensus
            .get_execution_payload(&Some(latest_header.slot))
            .await
            .map_err(NodeError::ConsensusPayloadError)?;

        let finalized_header = self.consensus.get_finalized_header();
        let finalized_payload = self
            .consensus
            .get_execution_payload(&Some(finalized_header.slot))
            .await
            .map_err(NodeError::ConsensusPayloadError)?;

        self.payloads
            .insert(latest_payload.block_number, latest_payload);
        self.payloads
            .insert(finalized_payload.block_number, finalized_payload.clone());
        self.finalized_payloads
            .insert(finalized_payload.block_number, finalized_payload);

        while self.payloads.len() > self.history_size {
            self.payloads.pop_first();
        }

        // only save one finalized block per epoch
        // finality updates only occur on epoch boundaries
        while self.finalized_payloads.len() > usize::max(self.history_size / 32, 1) {
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
        let transaction_count = payload.1.transactions.len();

        Ok(transaction_count as u64)
    }

    pub fn get_block_transaction_count_by_number(&self, block: BlockTag) -> Result<u64> {
        let payload = self.get_payload(block)?;
        let transaction_count = payload.transactions.len();

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
            payload.base_fee_per_gas.to_little_endian(&mut base_fee);
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
        Ok(payload.block_number)
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
        &self,
        tx_hash: &H256,
    ) -> Result<Option<CkbTransaction>> {
        let eth_transaction = match self.execution.rpc.get_transaction(tx_hash).await? {
            Some(tx) => tx,
            None => return Ok(None),
        };
        let eth_receipt = match self.execution.rpc.get_transaction_receipt(tx_hash).await? {
            Some(receipt) => receipt,
            None => return Ok(None),
        };
        let mut slot = 0;
        let mut eth_receipts = None;
        if let Some(block_number) = eth_transaction.block_number {
            if let Some(eth_slot) = self.block_number_slots.get(&block_number.as_u64()) {
                slot = *eth_slot;
            }
            match self.payloads.get(&block_number.as_u64()) {
                Some(payload) => {
                    let tx_hashes = payload
                        .transactions
                        .iter()
                        .map(|tx| H256::from_slice(&keccak256(tx.to_vec())))
                        .collect::<Vec<_>>();
                    let receipts_fut = tx_hashes.into_iter().map(|hash| async move {
                        let receipt = self.execution.rpc.get_transaction_receipt(&hash).await;
                        receipt?.ok_or(eyre::eyre!("not reachable"))
                    });

                    let receipts = join_all(receipts_fut).await;
                    eth_receipts = Some(receipts.into_iter().collect::<Result<Vec<_>>>()?);
                }
                None => return Ok(None),
            }
        }
        if slot > 0 && eth_receipts.is_some() {
            let block = self.consensus.rpc.get_block(slot).await?;
            let client = self
                .forcerelay
                .onchain_client()
                .await
                .map_err(NodeError::ConsensusSyncError)?;
            if self.consensus.base_slot() != client.minimal_slot {
                panic!("the light-client cell was re-deployed, the base slot was changed");
            }
            if slot < client.minimal_slot {
                return Err(eyre::eyre!("the block is old than the client"));
            }
            if slot > client.maximal_slot {
                return Err(eyre::eyre!("the block is new than the client"));
            }
            let ckb_transaction = self
                .forcerelay
                .assemble_tx(
                    &self.consensus,
                    &block,
                    &eth_transaction,
                    &eth_receipt,
                    &eth_receipts.unwrap(),
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
        let coinbase_address = Address::from_slice(payload.fee_recipient.as_bytes());
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
            .filter(|entry| entry.1.block_hash.into_root().as_bytes() == hash)
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

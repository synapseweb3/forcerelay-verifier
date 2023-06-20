use std::path::PathBuf;
use std::sync::Arc;

use config::networks::Network;
use config::ClientTypeArgs;
use ethers::prelude::{Address, U256};
use ethers::types::{Filter, Log, Transaction, TransactionReceipt, H256};
use eyre::{eyre, Result};

use common::types::BlockTag;
use config::Config;
use consensus::types::Header;
use execution::types::{CallOpts, ExecutionBlock};
use log::error;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::node::Node;
use crate::rpc::Rpc;

#[derive(Default)]
pub struct ClientBuilder {
    network: Option<Network>,
    consensus_rpc: Option<String>,
    execution_rpc: Option<String>,
    ckb_rpc: Option<String>,
    lightclient_contract_typeargs: Option<Vec<u8>>,
    lightclient_client_type_args: Option<ClientTypeArgs>,
    lightclient_binary_typeargs: Option<Vec<u8>>,
    ibc_client_id: Option<String>,
    checkpoint: Option<Vec<u8>>,
    rpc_port: Option<u16>,
    storage_path: Option<PathBuf>,
    config: Option<Config>,
    fallback: Option<String>,
    load_external_fallback: bool,
    strict_checkpoint_age: bool,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    pub fn consensus_rpc(mut self, consensus_rpc: &str) -> Self {
        self.consensus_rpc = Some(consensus_rpc.to_string());
        self
    }

    pub fn execution_rpc(mut self, execution_rpc: &str) -> Self {
        self.execution_rpc = Some(execution_rpc.to_string());
        self
    }

    pub fn ckb_rpc(mut self, ckb_rpc: &str) -> Self {
        self.ckb_rpc = Some(ckb_rpc.to_string());
        self
    }

    pub fn lightclient_contract_typeargs(mut self, typeargs: &str) -> Self {
        let typeargs = hex::decode(typeargs.strip_prefix("0x").unwrap_or(typeargs))
            .expect("cannot parse lightclient");
        self.lightclient_contract_typeargs = Some(typeargs);
        self
    }

    pub fn lightclient_client_type_args(mut self, client_type_args: ClientTypeArgs) -> Self {
        self.lightclient_client_type_args = Some(client_type_args);
        self
    }

    pub fn lightclient_binary_typeargs(mut self, typeargs: &str) -> Self {
        let typeargs = hex::decode(typeargs.strip_prefix("0x").unwrap_or(typeargs))
            .expect("cannot parse lightclient");
        self.lightclient_binary_typeargs = Some(typeargs);
        self
    }

    pub fn ibc_client_id(mut self, client_id: &str) -> Self {
        self.ibc_client_id = Some(client_id.to_owned());
        self
    }

    pub fn checkpoint(mut self, checkpoint: &str) -> Self {
        let checkpoint = hex::decode(checkpoint.strip_prefix("0x").unwrap_or(checkpoint))
            .expect("cannot parse checkpoint");
        self.checkpoint = Some(checkpoint);
        self
    }

    pub fn rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = Some(port);
        self
    }

    pub fn storage_path(mut self, storage_path: PathBuf) -> Self {
        self.storage_path = Some(storage_path);
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn fallback(mut self, fallback: &str) -> Self {
        self.fallback = Some(fallback.to_string());
        self
    }

    pub fn load_external_fallback(mut self) -> Self {
        self.load_external_fallback = true;
        self
    }

    pub fn strict_checkpoint_age(mut self) -> Self {
        self.strict_checkpoint_age = true;
        self
    }

    pub fn build(self) -> Result<(Client, Sender<()>)> {
        let base_config = if let Some(network) = self.network {
            network.to_base_config()
        } else {
            let config = self
                .config
                .as_ref()
                .ok_or(eyre!("missing network config"))?;
            config.to_base_config()
        };

        let consensus_rpc = self.consensus_rpc.unwrap_or_else(|| {
            self.config
                .as_ref()
                .expect("missing consensus rpc")
                .consensus_rpc
                .clone()
        });

        let execution_rpc = self.execution_rpc.unwrap_or_else(|| {
            self.config
                .as_ref()
                .expect("missing execution rpc")
                .execution_rpc
                .clone()
        });

        let ckb_rpc = self.ckb_rpc.unwrap_or_else(|| {
            self.config
                .as_ref()
                .expect("missing ckb rpc")
                .ckb_rpc
                .clone()
        });

        let lightclient_contract_typeargs =
            if let Some(typeargs) = self.lightclient_contract_typeargs {
                typeargs
            } else if let Some(config) = &self.config {
                config.lightclient_contract_typeargs.clone()
            } else {
                // TODO: isn't this field mandatory?
                vec![0u8; 32]
            };

        let lightclient_client_type_args = if let Some(typeargs) = self.lightclient_client_type_args
        {
            typeargs
        } else if let Some(config) = &self.config {
            config.lightclient_client_type_args.clone()
        } else {
            panic!("missing lightclient_client_type_args")
        };

        let lightclient_binary_typeargs = if let Some(typeargs) = self.lightclient_binary_typeargs {
            typeargs
        } else if let Some(config) = &self.config {
            config.lightclient_binary_typeargs.clone()
        } else {
            // TODO: isn't this field mandatory?
            vec![0u8; 32]
        };

        let client_id = if let Some(client_id) = self.ibc_client_id {
            client_id
        } else if let Some(config) = &self.config {
            config.ckb_ibc_client_id.clone()
        } else {
            String::new()
        };

        let checkpoint = if let Some(checkpoint) = self.checkpoint {
            checkpoint
        } else if let Some(config) = &self.config {
            config.checkpoint.clone()
        } else {
            base_config.checkpoint
        };

        let rpc_port = if self.rpc_port.is_some() {
            self.rpc_port
        } else if let Some(config) = &self.config {
            config.rpc_port
        } else {
            None
        };

        let storage_path = self.storage_path.unwrap_or_else(|| {
            self.config
                .as_ref()
                .expect("missing ckb mmr storage path")
                .storage_path
                .clone()
        });

        let fallback = if self.fallback.is_some() {
            self.fallback
        } else if let Some(config) = &self.config {
            config.fallback.clone()
        } else {
            None
        };

        let load_external_fallback = if let Some(config) = &self.config {
            self.load_external_fallback || config.load_external_fallback
        } else {
            self.load_external_fallback
        };

        let strict_checkpoint_age = if let Some(config) = &self.config {
            self.strict_checkpoint_age || config.strict_checkpoint_age
        } else {
            self.strict_checkpoint_age
        };

        let config = Config {
            consensus_rpc,
            execution_rpc,
            ckb_rpc,
            lightclient_contract_typeargs,
            lightclient_client_type_args,
            lightclient_binary_typeargs,
            ckb_ibc_client_id: client_id,
            checkpoint,
            rpc_port,
            storage_path,
            chain: base_config.chain,
            forks: base_config.forks,
            max_checkpoint_age: base_config.max_checkpoint_age,
            fallback,
            load_external_fallback,
            strict_checkpoint_age,
        };

        let (sender, receiver) = channel(1);
        Ok((Client::new(config, receiver)?, sender))
    }
}

pub struct Client {
    node: Arc<RwLock<Node>>,
    port: u16,
    rpc: Option<Rpc>,
    shutdown_receiver: Receiver<()>,
}

impl Client {
    fn new(config: Config, shutdown_receiver: Receiver<()>) -> Result<Self> {
        let config = Arc::new(config);
        let node = Node::new(config.clone())?;
        let port = config.rpc_port.expect("no rpc server");

        Ok(Client {
            node: Arc::new(RwLock::new(node)),
            rpc: None,
            port,
            shutdown_receiver,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        // start a mock rpc server to response IN-PROGRESS message
        let mut rpc = Rpc::new(self.node.clone(), self.port);
        rpc.start(false).await?;

        let mut node = self.node.write().await;
        tokio::select! {
            result = node.sync() => {
                if let Err(err) = result {
                    return Err(err.into());
                }
            },
            _ = self.shutdown_receiver.recv() => {
                return Ok(());
            }
        }
        rpc.stop().await?;

        // start a true rpc server
        let mut rpc = Rpc::new(self.node.clone(), self.port);
        rpc.start(true).await?;
        self.rpc = Some(rpc);

        let node = self.node.clone();
        spawn(async move {
            loop {
                if let Err(err) = node.write().await.advance().await {
                    error!("consensus error: {}", err);
                }

                let next_update = node.read().await.duration_until_next_update();
                sleep(next_update).await;
            }
        });

        Ok(())
    }

    pub async fn shutdown(&self) {
        self.node
            .read()
            .await
            .print_status_log(None)
            .await
            .expect("shutdown");
    }

    pub async fn call(&self, opts: &CallOpts, block: BlockTag) -> Result<Vec<u8>> {
        self.node
            .read()
            .await
            .call(opts, block)
            .await
            .map_err(|err| err.into())
    }

    pub async fn estimate_gas(&self, opts: &CallOpts) -> Result<u64> {
        self.node
            .read()
            .await
            .estimate_gas(opts)
            .await
            .map_err(|err| err.into())
    }

    pub async fn get_balance(&self, address: &Address, block: BlockTag) -> Result<U256> {
        self.node.read().await.get_balance(address, block).await
    }

    pub async fn get_nonce(&self, address: &Address, block: BlockTag) -> Result<u64> {
        self.node.read().await.get_nonce(address, block).await
    }

    pub async fn get_block_transaction_count_by_hash(&self, hash: &Vec<u8>) -> Result<u64> {
        self.node
            .read()
            .await
            .get_block_transaction_count_by_hash(hash)
    }

    pub async fn get_block_transaction_count_by_number(&self, block: BlockTag) -> Result<u64> {
        self.node
            .read()
            .await
            .get_block_transaction_count_by_number(block)
    }

    pub async fn get_code(&self, address: &Address, block: BlockTag) -> Result<Vec<u8>> {
        self.node.read().await.get_code(address, block).await
    }

    pub async fn get_storage_at(
        &self,
        address: &Address,
        slot: H256,
        block: BlockTag,
    ) -> Result<U256> {
        self.node
            .read()
            .await
            .get_storage_at(address, slot, block)
            .await
    }

    pub async fn send_raw_transaction(&self, bytes: &[u8]) -> Result<H256> {
        self.node.read().await.send_raw_transaction(bytes).await
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &H256,
    ) -> Result<Option<TransactionReceipt>> {
        self.node
            .read()
            .await
            .get_transaction_receipt(tx_hash)
            .await
    }

    pub async fn get_transaction_by_hash(&self, tx_hash: &H256) -> Result<Option<Transaction>> {
        self.node
            .read()
            .await
            .get_transaction_by_hash(tx_hash)
            .await
    }

    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        self.node.read().await.get_logs(filter).await
    }

    pub async fn get_gas_price(&self) -> Result<U256> {
        self.node.read().await.get_gas_price()
    }

    pub async fn get_priority_fee(&self) -> Result<U256> {
        self.node.read().await.get_priority_fee()
    }

    pub async fn get_block_number(&self) -> Result<u64> {
        self.node.read().await.get_block_number()
    }

    pub async fn get_block_by_number(
        &self,
        block: BlockTag,
        full_tx: bool,
    ) -> Result<Option<ExecutionBlock>> {
        self.node
            .read()
            .await
            .get_block_by_number(block, full_tx)
            .await
    }

    pub async fn get_block_by_hash(
        &self,
        hash: &Vec<u8>,
        full_tx: bool,
    ) -> Result<Option<ExecutionBlock>> {
        self.node
            .read()
            .await
            .get_block_by_hash(hash, full_tx)
            .await
    }

    pub async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: &Vec<u8>,
        index: usize,
    ) -> Result<Option<Transaction>> {
        self.node
            .read()
            .await
            .get_transaction_by_block_hash_and_index(block_hash, index)
            .await
    }

    pub async fn chain_id(&self) -> u64 {
        self.node.read().await.chain_id()
    }

    pub async fn get_header(&self) -> Result<Header> {
        self.node.read().await.get_header()
    }

    pub async fn get_coinbase(&self) -> Result<Address> {
        self.node.read().await.get_coinbase()
    }
}

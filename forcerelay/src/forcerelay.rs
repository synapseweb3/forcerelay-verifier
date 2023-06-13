use ckb_types::core::TransactionView;
use ckb_types::packed::CellDep;
use consensus::rpc::ConsensusRpc;
use consensus::ConsensusClient;
use eth2_types::MainnetEthSpec;
use eth_light_client_in_ckb_prover::CachedBeaconBlock;
use eth_light_client_in_ckb_verification::types::core::{
    Hash, Client as OnChainClient, ClientTypeArgs,
};
use ethers::types::{Transaction, TransactionReceipt};
use eyre::{eyre, Result};
use storage::prelude::StorageReader;

use crate::assembler::ForcerelayAssembler;
use crate::rpc::CkbRpc;

pub struct ForcerelayClient<R: CkbRpc> {
    assembler: ForcerelayAssembler<R>,
}

impl<R: CkbRpc> ForcerelayClient<R> {
    pub fn new(
        rpc: R,
        lightclient_contract_typeargs: &[u8],
        lightclient_client_type_args_type_id: &[u8],
        lightclient_client_type_args_cells_count: u8,
        binary_typeargs: &[u8],
    ) -> Self {
        let lightclient_client_type_args = ClientTypeArgs {
            type_id: Hash::from_slice(lightclient_client_type_args_type_id),
            cells_count: lightclient_client_type_args_cells_count,
        };
        let assembler =
            ForcerelayAssembler::new(
                rpc, lightclient_contract_typeargs, lightclient_client_type_args, binary_typeargs
            );
        Self { assembler }
    }

    pub async fn onchain_client(&self) -> Result<(OnChainClient, CellDep)> {
        if let Some(client) = self.assembler.fetch_onchain_latest_client().await? {
            Ok(client)
        } else {
            Err(eyre!("no lightclient cell deployed on ckb"))
        }
    }

    pub async fn check_onchain_client_alignment(
        &self,
        consensus: &ConsensusClient<impl ConsensusRpc>,
    ) -> Result<(OnChainClient, CellDep)> {
        let (client, celldep) = self.onchain_client().await?;
        if let Some(base_slot) = consensus.storage().get_base_beacon_header_slot()? {
            if let Some(tip_slot) = consensus.storage().get_tip_beacon_header_slot()? {
                if client.minimal_slot == base_slot && client.maximal_slot <= tip_slot {
                    return Ok((client, celldep));
                }
                return Err(eyre!(
                    "consensus storage [{base_slot}, {tip_slot}] is not aligned to onchain client [{}, {}], please wait a while...",
                    client.minimal_slot, client.maximal_slot
                ));
            }
        }
        Err(eyre!("consensus storage is not initialized"))
    }

    pub async fn update_assembler_celldep(&mut self) -> Result<()> {
        self.assembler.update_binary_celldep().await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn assemble_tx(
        &mut self,
        client: OnChainClient,
        client_celldep: &CellDep,
        consensus: &ConsensusClient<impl ConsensusRpc>,
        block: &CachedBeaconBlock<MainnetEthSpec>,
        tx: &Transaction,
        receipts: &[TransactionReceipt],
    ) -> Result<TransactionView> {
        self.assembler
            .assemble_tx(client, client_celldep, consensus, block, tx, receipts)
            .await
    }
}

#[cfg(test)]
mod test {
    use ckb_jsonrpc_types::TransactionView as JsonTxView;
    use ckb_types::core::{Capacity, ScriptHashType, TransactionView};
    use ckb_types::packed::{CellOutput, Script};
    use ckb_types::{bytes::Bytes, prelude::*};
    use ethers::types::{Transaction, TransactionReceipt};
    use eyre::Result;
    use std::{cell::RefCell, path::PathBuf, sync::Arc};
    use tempfile::TempDir;
    use test_utils::{Context, Verifier};

    use config::{networks, Config};
    use consensus::types::{BeaconBlock, Header};
    use consensus::{rpc::mock_rpc::MockRpc, ConsensusClient};

    use crate::forcerelay::ForcerelayClient;
    use crate::rpc::{MockRpcClient, BINARY_TYPEID_ARGS, CONTRACT_TYPEID_ARGS, TESTDATA_DIR};
    use crate::setup_test_logger;

    const BUSINESS_BIN: &str = "eth_light_client-mock_business_type_lock";
    const ALWAYS_SUCCESS: &str = "always_success";

    async fn make_consensus(path: PathBuf, last_header: &Header) -> ConsensusClient<MockRpc> {
        let base_config = networks::goerli();
        let config = Config {
            consensus_rpc: String::new(),
            execution_rpc: String::new(),
            chain: base_config.chain,
            forks: base_config.forks,
            max_checkpoint_age: u64::MAX,
            storage_path: path,
            ..Default::default()
        };

        let checkpoint =
            hex::decode("7bc1d0c64d28d63ddd8150bc92bff771011acbddfa314b8288b3fe0a7b3a01cb")
                .unwrap();

        let mut client = ConsensusClient::new(TESTDATA_DIR, &checkpoint, Arc::new(config)).unwrap();
        client.bootstrap(5763680).await.expect("bootstrap");
        client
            .store_updates_until_finality_update(&last_header.clone().into())
            .await
            .expect("until store");
        client
    }

    fn load_json_testdata<'a, V: serde::Deserialize<'a>>(filename: &str) -> Result<V> {
        let contents = std::fs::read(format!("{TESTDATA_DIR}{filename}"))?;
        let static_ref = Box::leak(Box::new(contents));
        let value: V = serde_json::from_slice(static_ref)?;
        Ok(value)
    }

    async fn assemble_partial_tx(
        forcerelay: &mut ForcerelayClient<MockRpcClient>,
        path: PathBuf,
    ) -> TransactionView {
        let headers: Vec<Header> = load_json_testdata("headers.json").expect("load headers");
        let consensus = make_consensus(path, headers.last().unwrap()).await;
        let block: BeaconBlock = load_json_testdata("block.json").expect("load block");
        let tx: Transaction = load_json_testdata("transaction.json").expect("load transaction");
        let receipts: Vec<TransactionReceipt> =
            load_json_testdata("receipts.json").expect("load receipts");
        let (client, client_celldep) = forcerelay
            .onchain_client()
            .await
            .expect("fetch light client");
        forcerelay
            .update_assembler_celldep()
            .await
            .expect("update binary celldep");
        forcerelay
            .assemble_tx(
                client,
                &client_celldep,
                &consensus,
                &block.into(),
                &tx,
                &receipts,
            )
            .await
            .expect("assemble partial")
    }

    fn complete_partial_tx(
        forcerelay: &ForcerelayClient<MockRpcClient>,
        context: Arc<RefCell<Context>>,
        tx: TransactionView,
    ) -> TransactionView {
        let mut context = context.borrow_mut();
        // prepare always_success
        let (always_success_lock, always_success_contract) = {
            let data = std::fs::read(format!("{TESTDATA_DIR}lightclient/{ALWAYS_SUCCESS}"))
                .expect("read always_success");
            let deployed_cell = context.deploy(data.into(), Default::default(), None);
            let lock = Script::new_builder()
                .code_hash(deployed_cell.data_hash())
                .hash_type(ScriptHashType::Data1.into())
                .build();
            let celldep = deployed_cell.as_cell_dep();
            (lock, celldep)
        };
        let mock_output = CellOutput::new_builder()
            .lock(always_success_lock.clone())
            .build_exact_capacity(Capacity::zero())
            .unwrap();
        // prepare mock business
        let business_args = {
            let mut data = vec![];
            let lightclient_hash = forcerelay
                .assembler
                .lightclient_typescript
                .calc_script_hash();
            let binary_hash = forcerelay.assembler.binary_typeid_script.calc_script_hash();
            data.append(&mut lightclient_hash.as_slice().to_vec());
            data.append(&mut binary_hash.as_bytes().to_vec());
            data
        };
        let data = std::fs::read(format!("{TESTDATA_DIR}lightclient/{BUSINESS_BIN}"))
            .expect("read business");
        let business_type = Script::new_builder()
            .code_hash(CellOutput::calc_data_hash(&data))
            .hash_type(ScriptHashType::Data1.into())
            .args(business_args.pack())
            .build();
        let deployed_business_contract = context.deploy(data.into(), Default::default(), None);
        let business_cell = {
            let deployed_cell =
                context.deploy(Default::default(), always_success_lock, Some(business_type));
            deployed_cell.as_input()
        };
        // rebuild tx
        tx.as_advanced_builder()
            .cell_dep(always_success_contract)
            .cell_dep(deployed_business_contract.as_cell_dep())
            .input(business_cell)
            .output(mock_output)
            .output_data(Bytes::new().pack())
            .build()
    }

    #[tokio::test]
    async fn test_assemble_tx() {
        setup_test_logger();
        let context = Arc::new(RefCell::new(Context::default()));
        let mut forcerelay = ForcerelayClient::new(
            MockRpcClient::new(context.clone()),
            &CONTRACT_TYPEID_ARGS.to_vec(),
            &BINARY_TYPEID_ARGS.to_vec(),
            "client_id",
        );

        // generate tx
        let path = TempDir::new().unwrap();
        let tx = assemble_partial_tx(&mut forcerelay, path.into_path()).await;
        let tx = complete_partial_tx(&forcerelay, context.clone(), tx);

        // run tx
        let rtx = context.borrow().resolve(tx.clone());
        let verifier = Verifier::default();
        let cycles = verifier.verify_without_limit(&rtx);
        match cycles {
            Ok(value) => println!("consume cycles: {value}"),
            Err(error) => {
                let json_tx = serde_json::to_string_pretty(&JsonTxView::from(tx)).unwrap();
                println!("tx = {json_tx}");
                panic!("{error}");
            }
        }
    }
}

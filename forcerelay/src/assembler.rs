use ckb_types::core::{DepType, ScriptHashType, TransactionView};
use ckb_types::packed::{CellDep, Script};
use ckb_types::prelude::{Builder, Entity, Pack};
use consensus::rpc::ConsensusRpc;
use consensus::ConsensusClient;
use eth2_types::MainnetEthSpec;
use eth_light_client_in_ckb_prover::CachedBeaconBlock;
use eth_light_client_in_ckb_verification::mmr;
use eth_light_client_in_ckb_verification::types::{
    core::{self, Client, ClientTypeArgs},
    packed::{Client as PackedClient, ClientInfo as PackedClientInfo},
    prelude::{Pack as LcPack, Unpack as LcUnpack},
};
use ethers::types::{Transaction, TransactionReceipt};
use eyre::Result;
use storage::prelude::StorageAsMMRStore as _;

use crate::rpc::CkbRpc;
use crate::util::*;

pub struct ForcerelayAssembler<R: CkbRpc> {
    rpc: R,
    binary_celldep: CellDep,
    pub binary_typeid_script: Script,
    pub lightclient_typescript: Script,
    lightclient_client_type_args: ClientTypeArgs,
}

impl<R: CkbRpc> ForcerelayAssembler<R> {
    pub fn new(
        rpc: R,
        lightclient_contract_typeargs: &[u8],
        lightclient_client_type_args: ClientTypeArgs,
        binary_typeargs: &[u8],
    ) -> Self {
        let contract_typeid_script = make_typeid_script(lightclient_contract_typeargs);
        let binary_typeid_script = make_typeid_script(binary_typeargs);

        let lightclient_typescript = {
            let contract_hash = contract_typeid_script.calc_script_hash();
            Script::new_builder()
                .code_hash(contract_hash)
                .args(lightclient_client_type_args.pack().as_slice().pack())
                .hash_type(ScriptHashType::Type.into())
                .build()
        };
        Self {
            rpc,
            binary_celldep: CellDep::default(),
            binary_typeid_script,
            lightclient_typescript,
            lightclient_client_type_args,
        }
    }

    pub async fn fetch_onchain_latest_client(&self) -> Result<Option<(Client, CellDep)>> {
        let Some((client_cells, client_info_cell)) = fetch_multi_client_cells(
            &self.rpc,
            &self.lightclient_typescript,
            &self.lightclient_client_type_args,
        ).await?
        else {
            return Ok(None)
        };
        let client_info = PackedClientInfo::new_unchecked(client_info_cell.output_data).unpack();
        let ret = client_cells.iter().find_map(|cell| {
            let client = PackedClient::new_unchecked(cell.output_data.clone());
            if client.id() == client_info.last_id.into() {
                let celldep = CellDep::new_builder()
                    .out_point(cell.out_point.clone())
                    .dep_type(DepType::Code.into())
                    .build();
                Some((client.unpack(), celldep))
            } else {
                None
            }
        });
        Ok(ret)
    }

    pub async fn update_binary_celldep(&mut self) -> Result<()> {
        if let Some(binary_celldep) =
            search_cell_as_celldep(&self.rpc, &self.binary_typeid_script).await?
        {
            self.binary_celldep = binary_celldep;
            Ok(())
        } else {
            Err(eyre::eyre!("light client binary cell not found"))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn assemble_tx(
        &mut self,
        client: core::Client,
        client_celldep: &CellDep,
        consensus: &ConsensusClient<impl ConsensusRpc>,
        block: &CachedBeaconBlock<MainnetEthSpec>,
        tx: &Transaction,
        receipts: &[TransactionReceipt],
    ) -> Result<TransactionView> {
        let receipts = receipts.to_owned().into();

        let header_mmr_proof = {
            let mmr = consensus.storage().chain_root_mmr(client.maximal_slot)?;
            let mmr_position = block.slot() - client.minimal_slot;
            let mmr_index = mmr::lib::leaf_index_to_pos(mmr_position.into());
            mmr.gen_proof(vec![mmr_index])?
                .proof_items()
                .iter()
                .map(LcUnpack::unpack)
                .collect::<Vec<_>>()
        };

        let transaction_index = match find_receipt_index(tx.hash, &receipts) {
            Some(index) => index,
            None => return Err(eyre::eyre!("cannot find receipt from receipts")),
        };
        let packed_proof = generate_packed_transaction_proof(
            block,
            &receipts,
            transaction_index,
            &header_mmr_proof,
        )?;
        client
            .verify_packed_transaction_proof(packed_proof.as_reader())
            .map_err(|e| eyre::eyre!("verify transaction proof error {}", e as i8))?;
        let packed_payload = generate_packed_payload(block, tx, &receipts, transaction_index)?;
        packed_proof
            .unpack()
            .verify_packed_payload(packed_payload.as_reader())
            .map_err(|e| eyre::eyre!("verify payload proof error {}", e as i8))?;

        let celldeps = vec![self.binary_celldep.clone(), client_celldep.clone()];
        assemble_partial_verification_transaction(&packed_proof, &packed_payload, &celldeps)
    }
}

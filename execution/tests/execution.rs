use std::collections::BTreeMap;
use std::str::FromStr;

use eth2_types::Hash256;
use ethers::types::{Address, Filter, H256, U256};
use execution::rpc::http_rpc::HttpRpc;
use execution::rpc::ExecutionRpc;
// use ssz_rs::{List, Vector};
use ssz_types::VariableList as List;

use common::utils::hex_str_to_bytes;
use consensus::types::{ExecutionPayload, ExecutionPayloadMerge};
use execution::rpc::mock_rpc::MockRpc;
use execution::ExecutionClient;

fn get_client() -> ExecutionClient<MockRpc> {
    ExecutionClient::new("testdata/").unwrap()
}

#[tokio::test]
async fn test_get_account() {
    let execution = get_client();
    let address = Address::from_str("14f9D4aF749609c1438528C0Cce1cC3f6D411c47").unwrap();

    let state_root =
        Hash256::from_str("0xaa02f5db2ee75e3da400d10f3c30e894b6016ce8a2501680380a907b6674ce0d")
            .unwrap();
    let merge = ExecutionPayloadMerge {
        state_root,
        ..ExecutionPayloadMerge::default()
    };
    let payload = ExecutionPayload::Merge(merge);

    let account = execution
        .get_account(&address, None, &payload)
        .await
        .unwrap();

    assert_eq!(
        account.balance,
        U256::from_str_radix("48c27395000", 16).unwrap()
    );
}

#[tokio::test]
async fn test_get_account_bad_proof() {
    let execution = get_client();
    let address = Address::from_str("14f9D4aF749609c1438528C0Cce1cC3f6D411c47").unwrap();
    let merge = ExecutionPayloadMerge::default();
    let payload = ExecutionPayload::Merge(merge);

    let account_res = execution.get_account(&address, None, &payload).await;

    assert!(account_res.is_err());
}

#[tokio::test]
async fn test_get_tx() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let mut merge = ExecutionPayloadMerge::default();
    merge.transactions.push(List::from(hex_str_to_bytes("0x02f8b20583623355849502f900849502f91082ea6094326c977e6efc84e512bb9c30f76e30c160ed06fb80b844a9059cbb0000000000000000000000007daccf9b3c1ae2fa5c55f1c978aeef700bc83be0000000000000000000000000000000000000000000000001158e460913d00000c080a0e1445466b058b6f883c0222f1b1f3e2ad9bee7b5f688813d86e3fa8f93aa868ca0786d6e7f3aefa8fe73857c65c32e4884d8ba38d0ecfb947fbffb82e8ee80c167").unwrap())).unwrap();
    let payload = ExecutionPayload::Merge(merge);

    let mut payloads = BTreeMap::new();
    payloads.insert(7530933, payload);

    let tx = execution
        .get_transaction(&tx_hash, &payloads)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(tx.hash(), tx_hash);
}

#[tokio::test]
async fn test_get_tx_bad_proof() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let merge = ExecutionPayloadMerge::default();
    let payload = ExecutionPayload::Merge(merge);

    let mut payloads = BTreeMap::new();
    payloads.insert(7530933, payload);

    let tx_res = execution.get_transaction(&tx_hash, &payloads).await;

    assert!(tx_res.is_err());
}

#[tokio::test]
async fn test_get_tx_not_included() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let payloads = BTreeMap::new();

    let tx_opt = execution
        .get_transaction(&tx_hash, &payloads)
        .await
        .unwrap();

    assert!(tx_opt.is_none());
}

#[tokio::test]
async fn test_get_logs() {
    let execution = get_client();
    let receipts_root =
        Hash256::from_str("0xdd82a78eccb333854f0c99e5632906e092d8a49c27a21c25cae12b82ec2a113f")
            .unwrap();
    let mut merge = ExecutionPayloadMerge {
        receipts_root,
        ..ExecutionPayloadMerge::default()
    };

    merge.transactions.push(List::from(hex_str_to_bytes("0x02f8b20583623355849502f900849502f91082ea6094326c977e6efc84e512bb9c30f76e30c160ed06fb80b844a9059cbb0000000000000000000000007daccf9b3c1ae2fa5c55f1c978aeef700bc83be0000000000000000000000000000000000000000000000001158e460913d00000c080a0e1445466b058b6f883c0222f1b1f3e2ad9bee7b5f688813d86e3fa8f93aa868ca0786d6e7f3aefa8fe73857c65c32e4884d8ba38d0ecfb947fbffb82e8ee80c167").unwrap())).unwrap();
    let payload = ExecutionPayload::Merge(merge);

    let mut payloads = BTreeMap::new();
    payloads.insert(7530933, payload);

    let filter = Filter::new();
    let logs = execution.get_logs(&filter, &payloads).await.unwrap();

    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    assert!(!logs.is_empty());
    assert!(logs[0].transaction_hash.is_some());
    assert!(logs[0].transaction_hash.unwrap() == tx_hash);
}

#[tokio::test]
async fn test_get_receipt() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let receipts_root =
        Hash256::from_str("0xdd82a78eccb333854f0c99e5632906e092d8a49c27a21c25cae12b82ec2a113f")
            .unwrap();
    let mut merge = ExecutionPayloadMerge {
        receipts_root,
        ..ExecutionPayloadMerge::default()
    };

    merge.transactions.push(List::from(hex_str_to_bytes("0x02f8b20583623355849502f900849502f91082ea6094326c977e6efc84e512bb9c30f76e30c160ed06fb80b844a9059cbb0000000000000000000000007daccf9b3c1ae2fa5c55f1c978aeef700bc83be0000000000000000000000000000000000000000000000001158e460913d00000c080a0e1445466b058b6f883c0222f1b1f3e2ad9bee7b5f688813d86e3fa8f93aa868ca0786d6e7f3aefa8fe73857c65c32e4884d8ba38d0ecfb947fbffb82e8ee80c167").unwrap())).unwrap();
    let payload = ExecutionPayload::Merge(merge);

    let mut payloads = BTreeMap::new();
    payloads.insert(7530933, payload);

    let receipt = execution
        .get_transaction_receipt(&tx_hash, &payloads)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(receipt.transaction_hash, tx_hash);
}

#[tokio::test]
async fn test_get_receipt_bad_proof() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let mut merge = ExecutionPayloadMerge::default();
    merge.transactions.push(List::from(hex_str_to_bytes("0x02f8b20583623355849502f900849502f91082ea6094326c977e6efc84e512bb9c30f76e30c160ed06fb80b844a9059cbb0000000000000000000000007daccf9b3c1ae2fa5c55f1c978aeef700bc83be0000000000000000000000000000000000000000000000001158e460913d00000c080a0e1445466b058b6f883c0222f1b1f3e2ad9bee7b5f688813d86e3fa8f93aa868ca0786d6e7f3aefa8fe73857c65c32e4884d8ba38d0ecfb947fbffb82e8ee80c167").unwrap())).unwrap();
    let payload = ExecutionPayload::Merge(merge);

    let mut payloads = BTreeMap::new();
    payloads.insert(7530933, payload);

    let receipt_res = execution.get_transaction_receipt(&tx_hash, &payloads).await;

    assert!(receipt_res.is_err());
}

#[tokio::test]
async fn test_get_receipt_not_included() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let payloads = BTreeMap::new();
    let receipt_opt = execution
        .get_transaction_receipt(&tx_hash, &payloads)
        .await
        .unwrap();

    assert!(receipt_opt.is_none());
}

#[tokio::test]
async fn test_get_block() {
    let execution = get_client();
    let merge = ExecutionPayloadMerge {
        block_number: 12345,
        ..ExecutionPayloadMerge::default()
    };
    let payload = ExecutionPayload::Merge(merge);

    let block = execution.get_block(&payload, false).await.unwrap();

    assert_eq!(block.number, 12345);
}

#[tokio::test]
async fn test_get_tx_by_block_hash_and_index() {
    let execution = get_client();
    let tx_hash =
        H256::from_str("2dac1b27ab58b493f902dda8b63979a112398d747f1761c0891777c0983e591f").unwrap();

    let mut merge = ExecutionPayloadMerge {
        block_number: 7530933,
        ..ExecutionPayloadMerge::default()
    };
    merge.transactions.push(List::from(hex_str_to_bytes("0x02f8b20583623355849502f900849502f91082ea6094326c977e6efc84e512bb9c30f76e30c160ed06fb80b844a9059cbb0000000000000000000000007daccf9b3c1ae2fa5c55f1c978aeef700bc83be0000000000000000000000000000000000000000000000001158e460913d00000c080a0e1445466b058b6f883c0222f1b1f3e2ad9bee7b5f688813d86e3fa8f93aa868ca0786d6e7f3aefa8fe73857c65c32e4884d8ba38d0ecfb947fbffb82e8ee80c167").unwrap())).unwrap();
    let payload = ExecutionPayload::Merge(merge);

    let tx = execution
        .get_transaction_by_block_hash_and_index(&payload, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tx.hash(), tx_hash);
}

#[tokio::test]
#[ignore]
async fn fetch_block_transaction_and_receipts() {
    const HTTP_RPC: &str = "https://eth-mainnet.g.alchemy.com/v2/XXXXX/";
    const BLOCK_NUMBER: u64 = 16594788;
    const TX_INDEX: usize = 0;
    const EXPORT_PATH: &str = "../forcerelay/testdata";

    let rpc = HttpRpc::new(HTTP_RPC).expect("http rpc");
    let block = rpc
        .get_block(BLOCK_NUMBER)
        .await
        .expect("block")
        .expect("invalid block hash");

    assert!(!block.transactions.is_empty());
    let transaction = rpc
        .get_transaction(&block.transactions[TX_INDEX])
        .await
        .expect("transaction")
        .unwrap();
    let contents = serde_json::to_string_pretty(&transaction).expect("tx jsonify");
    std::fs::write(format!("{EXPORT_PATH}/transaction.json"), contents).expect("write tx");

    let receipts = rpc
        .get_block_receipts(block.number.unwrap().as_u64())
        .await
        .expect("receipts");
    assert_eq!(receipts.len(), block.transactions.len());
    let contents = serde_json::to_string_pretty(&receipts).expect("receipts jsonify");
    std::fs::write(format!("{EXPORT_PATH}/receipts.json"), contents).expect("write receipts");
}

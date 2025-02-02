use common::errors::BlockNotFoundError;
use execution::errors::EvmError;
use eyre::Report;
use thiserror::Error;

/// Errors that can occur during Node calls
#[derive(Debug, Error)]
pub enum NodeError {
    #[error(transparent)]
    ExecutionError(#[from] EvmError),

    #[error("out of sync: {0} slots behind")]
    OutOfSync(u64),

    #[error("consensus payload error: {0}")]
    ConsensusPayloadError(Report),

    #[error("consensus client creation error: {0}")]
    ConsensusClientCreationError(Report),

    #[error("execution client creation error: {0}")]
    ExecutionClientCreationError(Report),

    #[error("consensus advance error: {0}")]
    ConsensusAdvanceError(Report),

    #[error("consensus sync error: {0}")]
    ConsensusSyncError(Report),

    #[error("forcerelay error: {0}")]
    ForcerelayError(Report),

    #[error(transparent)]
    BlockNotFoundError(#[from] BlockNotFoundError),

    #[error("transaction's block {0} is out of workable range [{1}, {2}]")]
    BlockNumberToSlotError(u64, u64, u64),
}

impl NodeError {
    pub fn to_json_rpsee_error(self) -> jsonrpsee::core::Error {
        match self {
            NodeError::ExecutionError(evm_err) => match evm_err {
                EvmError::Revert(data) => {
                    let mut msg = "execution reverted".to_string();
                    if let Some(reason) = data.as_ref().and_then(EvmError::decode_revert_reason) {
                        msg = format!("{msg}: {reason}")
                    }
                    jsonrpsee::core::Error::Call(jsonrpsee::types::error::CallError::Custom(
                        jsonrpsee::types::error::ErrorObject::owned(
                            3,
                            msg,
                            data.map(|data| format!("0x{}", hex::encode(data))),
                        ),
                    ))
                }
                _ => jsonrpsee::core::Error::Custom(evm_err.to_string()),
            },
            _ => jsonrpsee::core::Error::Custom(self.to_string()),
        }
    }
}

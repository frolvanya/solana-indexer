use std::str::FromStr;

use anchor_lang::prelude::borsh;
use anchor_lang::AnchorDeserialize;
use anyhow::Result;
use futures_util::StreamExt;

use solana_client::nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient};
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter};
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::signature::Signature;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use solana_transaction_status::{UiMessage, UiRawMessage, UiTransaction, UiTransactionEncoding};

const INIT_TRANSFER_DISCRIMINATOR: [u8; 8] = [174, 50, 134, 99, 122, 243, 243, 224];
const FINALIZE_TRANSFER_DISCRIMINATOR: [u8; 8] = [124, 126, 103, 188, 144, 65, 135, 51];

#[derive(Debug, AnchorDeserialize)]
pub struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
}

#[derive(Debug, AnchorDeserialize)]
pub struct TransferId {
    pub origin_chain: u8,
    pub origin_nonce: u64,
}

#[derive(Debug, AnchorDeserialize)]
pub struct FinalizeTransferPayload {
    pub destination_nonce: u64,
    pub transfer_id: TransferId,
    pub amount: u128,
    pub fee_recipient: Option<String>,
}

#[tokio::main]
async fn main() {
    let ws_url = "wss://api.devnet.solana.com";
    let http_url = "https://api.devnet.solana.com";

    let program_account = "Gy1XPwYZURfBzHiGAxnw3SYC33SfqsEpGSS5zeBge28p";

    if let Err(e) = fetch_recent_logs(http_url, program_account).await {
        eprintln!("Failed to fetch recent logs: {}", e);
    }

    if let Ok(client) = PubsubClient::new(ws_url).await {
        let filter = RpcTransactionLogsFilter::Mentions(vec![program_account.to_string()]);
        let config = RpcTransactionLogsConfig {
            commitment: Some(CommitmentConfig::processed()),
        };

        match client.logs_subscribe(filter, config).await {
            Ok((mut log_stream, _unsubscribe)) => {
                println!("Subscribed to live Solana logs!");

                while let Some(log) = log_stream.next().await {
                    println!("{:?}", log.value);
                }
            }
            Err(e) => {
                eprintln!("Failed to subscribe to logs: {}", e);
            }
        }
    } else {
        eprintln!("Failed to connect to WebSocket");
    }
}

async fn fetch_recent_logs(http_url: &str, program_account: &str) -> Result<()> {
    let rpc_client = RpcClient::new(http_url.to_string());
    let pubkey = Pubkey::from_str(program_account)?;

    let mut last_signature = None;

    loop {
        let signatures: Vec<RpcConfirmedTransactionStatusWithSignature> = rpc_client
            .get_signatures_for_address_with_config(
                &pubkey,
                GetConfirmedSignaturesForAddress2Config {
                    limit: None,
                    before: last_signature,
                    until: None,
                    commitment: Some(CommitmentConfig::confirmed()),
                },
            )
            .await?;

        if signatures.is_empty() {
            break;
        }

        for sig_status in &signatures {
            let signature = Signature::from_str(&sig_status.signature)?;

            if let Ok(tx) = rpc_client
                .get_transaction(&signature, UiTransactionEncoding::Json)
                .await
            {
                let transaction = tx.transaction.transaction;
                match transaction {
                    solana_transaction_status::EncodedTransaction::Json(tx) => {
                        print_tx_info(&tx, signature)?;
                    }
                    _ => {
                        eprintln!("Unsupported transaction encoding");
                    }
                }
            }
        }

        last_signature = signatures
            .last()
            .and_then(|s| Signature::from_str(&s.signature).ok());
    }

    Ok(())
}

fn print_tx_info(tx: &UiTransaction, signature: Signature) -> Result<()> {
    match tx.message {
        UiMessage::Parsed(_) => panic!("Unsupported transaction encoding"),
        UiMessage::Raw(ref raw) => print_raw_message(raw, signature),
    }

    Ok(())
}

fn print_raw_message(message: &UiRawMessage, signature: Signature) {
    for instruction in message.instructions.clone() {
        let index = instruction.program_id_index as usize;
        let program_id = message.account_keys[index].clone();

        if let Some(method) = decode_instruction(&instruction.data) {
            println!("Transaction Signature: {}", signature);
            println!("Transaction Message (raw):");
            println!("  Account Keys: {:?}", message.account_keys);
            println!("  Recent Blockhash: {:?}", message.recent_blockhash);
            println!("Program ID: {}, Method: {:?}\n", program_id, method);
        }
    }
}

fn decode_instruction(data: &str) -> Option<String> {
    let decoded_data = bs58::decode(data).into_vec().ok()?;
    println!("Raw data: {:?}", decoded_data);

    if decoded_data.starts_with(&INIT_TRANSFER_DISCRIMINATOR) {
        let payload_data = &decoded_data[8..];

        if let Ok(payload) = InitTransferPayload::try_from_slice(payload_data) {
            Some(format!("init_transfer: {:?}", payload))
        } else {
            Some("init_transfer: Data cannot be deserialized".to_string())
        }
    } else if decoded_data.starts_with(&FINALIZE_TRANSFER_DISCRIMINATOR) {
        let payload_data = &decoded_data[8..];
        match FinalizeTransferPayload::try_from_slice(payload_data) {
            Ok(payload) => println!("{:?}", payload),
            Err(err) => println!("Failed to deserialize payload: {:?}", err),
        }
        if let Ok(payload) = FinalizeTransferPayload::try_from_slice(payload_data) {
            Some(format!("finalize_transfer: {:?}", payload))
        } else {
            Some("finalize_transfer: Data cannot be deserialized".to_string())
        }
    } else {
        None
    }
}

use std::str::FromStr;

use anyhow::Result;
use futures_util::StreamExt;

use solana_client::nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient};
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter};
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::signature::Signature;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use solana_transaction_status::{UiMessage, UiRawMessage, UiTransactionEncoding};
use solana_transaction_status_client_types::UiTransaction;

const FINALIZE_DEPOSIT_DISCRIMINATOR: [u8; 8] = [240, 178, 165, 14, 221, 29, 104, 47];
const FINALIZE_WITHDRAW_DISCRIMINATOR: [u8; 8] = [17, 72, 11, 172, 214, 42, 12, 23];

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
    println!();
    println!("Transaction Signature: {}", signature);

    match tx.message {
        UiMessage::Parsed(_) => panic!("Unsupported transaction encoding"),
        UiMessage::Raw(ref raw) => print_raw_message(raw),
    }

    Ok(())
}

fn print_raw_message(message: &UiRawMessage) {
    println!("Transaction Message (raw):");
    println!("  Account Keys: {:?}", message.account_keys);
    println!("  Recent Blockhash: {:?}", message.recent_blockhash);

    for instruction in message.instructions.clone() {
        let index = instruction.program_id_index as usize;
        let program_id = message.account_keys[index].clone();
        let method = decode_instruction(&instruction.data);

        println!("Program ID: {}, Method: {:?}", program_id, method);
    }
}

fn decode_instruction(data: &str) -> Option<String> {
    let decoded_data = bs58::decode(data).into_vec().ok()?;
    println!("Raw Data: {:?}", data);
    println!("Decoded Data: {:?}", decoded_data);

    if decoded_data.starts_with(&FINALIZE_DEPOSIT_DISCRIMINATOR) {
        Some("finalize_deposit".to_string())
    } else if decoded_data.starts_with(&FINALIZE_WITHDRAW_DISCRIMINATOR) {
        Some("finalize_withdraw".to_string())
    } else {
        None
    }
}

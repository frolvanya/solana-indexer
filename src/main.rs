use std::str::FromStr;

use futures_util::StreamExt;

use solana_client::nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient};
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter};
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_sdk::signature::Signature;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use solana_transaction_status::UiTransactionEncoding;

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

async fn fetch_recent_logs(
    http_url: &str,
    program_account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_client = RpcClient::new(http_url.to_string());
    let pubkey = Pubkey::from_str(program_account)?;

    let mut last_signature = None;

    loop {
        let signatures: Vec<RpcConfirmedTransactionStatusWithSignature> = rpc_client
            .get_signatures_for_address_with_config(
                &pubkey,
                GetConfirmedSignaturesForAddress2Config {
                    limit: Some(1000),
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
                if let Some(meta) = tx.transaction.meta {
                    println!("Transaction details: {:?}", meta.log_messages);
                }
            }
        }

        last_signature = signatures
            .last()
            .and_then(|s| Signature::from_str(&s.signature).ok());
    }

    Ok(())
}
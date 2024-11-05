use std::collections::HashMap;
use std::env;
use std::time::Duration;
use dotenv::dotenv;
use thiserror::Error;
use tokio::{fs, task};
pub const SHARES_ENV_VAR_KEY: &str = "SHARES";
pub const THRESHOLD_ENV_VAR_KEY: &str = "THRESHOLD";
pub const DEFAULT_SHARES: u32 = 2;
pub const DEFAULT_THRESHOLD: u32 = 2;
pub fn get_shares() -> u32 {
    dotenv().ok();
    match env::var(SHARES_ENV_VAR_KEY) {
        Ok(value) => value
            .parse()
            .expect(format!("Invalid value for shares: {}", value).as_str()),
        Err(_) => DEFAULT_SHARES,
    }
}

pub fn get_threshold() -> u32 {
    dotenv().ok();
    match env::var(THRESHOLD_ENV_VAR_KEY) {
        Ok(value) => value
            .parse()
            .expect(format!("Invalid value for threshold: {}", value).as_str()),
        Err(_) => DEFAULT_THRESHOLD,
    }
}

pub const MESSAGE: &[u8; 25] = b"Is it secret? is it safe?";
pub const CONTEXT: &[u8; 28] = b"Keep it secret, keep it safe";
pub const FINALIZED: &str = "finalized";
pub const CONFIRMED: &str = "confirmed";
pub const HEART_BEAT: Duration = Duration::from_secs(3);

pub const DATA_DIR: &str = "data";

pub async fn ensure_data_dir() {
    if !fs::metadata(DATA_DIR).await.is_ok() {
        fs::create_dir_all(DATA_DIR).await.unwrap();
    }
}

pub async fn get_published_participant_file_name(participant_index: u32) -> String {
    ensure_data_dir().await;
    format!("{}/participant_{}", DATA_DIR, participant_index)
}

pub async fn get_their_secret_shares_file_name(participant_index: u32) -> String {
    ensure_data_dir().await;
    format!(
        "{}/participant_{}_their_secret_shares",
        DATA_DIR, participant_index
    )
}

pub async fn get_public_key_file_name(participant_index: u32) -> String {
    ensure_data_dir().await;
    format!("{}/participant_{}_pk.json", DATA_DIR, participant_index)
}

pub async fn get_signers_file_name() -> String {
    ensure_data_dir().await;
    format!("{}/signers.json", DATA_DIR)
}

pub async fn get_partial_signature_file_name(participant_index: u32) -> String {
    ensure_data_dir().await;
    format!(
        "{}/participant_{}_partial_signature.json",
        DATA_DIR, participant_index
    )
}

#[allow(unused)]
pub async fn get_finalization_confirmation_file_name(participant_index: u32) -> String {
    ensure_data_dir().await;
    format!(
        "{}/participant_{}_finalization_confirmation.txt",
        DATA_DIR, participant_index
    )
}

#[allow(unused)]
pub async fn get_finalized_file_name() -> String {
    ensure_data_dir().await;
    format!("{}/finalized.txt", DATA_DIR)
}

#[allow(unused)]
pub async fn delete_my_files(i: u32) -> Result<()> {
    let path = get_partial_signature_file_name(i).await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }

    let path = get_public_key_file_name(i).await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }

    let path = get_their_secret_shares_file_name(i).await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }

    let path = get_published_participant_file_name(i).await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }
    Ok(())
}

#[allow(unused)]
pub async fn delete_common_files() -> Result<()> {
    let path = get_signers_file_name().await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }

    let path = get_finalized_file_name().await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }

    let path = get_signers_file_name().await;
    if fs::metadata(path.clone()).await.is_ok() {
        fs::remove_file(path).await?;
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error occurred: {0:?}")]
    IO(#[from] tokio::io::Error),

    #[error("Serialization/Deserialization error: {0:?}")]
    Serde(#[from] serde_json::error::Error),

    #[error("Bincode error: {0:?}")]
    Bincode(#[from] bincode::Error),

    #[error("Misbehaving participant(s) detected: {0:?}")]
    MisbehavingDkg(Vec<u32>),

    #[error("Misbehaving participant(s) detected: {0:?}")]
    MisbehavingFinalization(HashMap<u32, &'static str>),

    #[error("Insufficient number of secret shares provided or verification failed")]
    InsufficientSecretShares,

    #[error("Failed to complete DKG process")]
    DkgFinishFailure,

    #[error("Task join error: {0}")]
    Task(#[from] task::JoinError),

    #[error("Signing error: {0}")]
    Signing(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;

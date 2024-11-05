use crate::Result;
use std::time::Duration;
use tokio::fs;
pub const SHARES: usize = 5;
pub const THRESHOLD: u32 = 3;

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
    format!("{}/participant_{}", DATA_DIR, participant_index)
}

pub async fn get_their_secret_shares_file_name(participant_index: u32) -> String {
    format!(
        "{}/participant_{}_their_secret_shares",
        DATA_DIR, participant_index
    )
}

pub async fn get_public_key_file_name(participant_index: u32) -> String {
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

pub async fn get_finalization_confirmation_file_name(participant_index: u32) -> String {
    ensure_data_dir().await;
    format!(
        "{}/participant_{}_finalization_confirmation.txt",
        DATA_DIR, participant_index
    )
}

pub async fn get_finalized_file_name() -> String {
    format!("{}/finalized.txt", DATA_DIR)
}

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

use crate::Result;
use std::time::Duration;
use tokio::fs;
pub const SHARES: usize = 2;
pub const THRESHOLD: u32 = 2;

pub const MESSAGE: &[u8; 25] = b"Is it secret? is it safe?";
pub const CONTEXT: &[u8; 28] = b"Keep it secret, keep it safe";
pub const FINALIZED: &str = "finalized";
pub const HEART_BEAT: Duration = Duration::from_secs(3);

pub const DATA_DIR: &str = ".";
pub fn get_published_participant_file_name(participant_index: u32) -> String {
    format!("{}/participant_{}", DATA_DIR, participant_index)
}

pub fn get_their_secret_shares_file_name(participant_index: u32) -> String {
    format!(
        "{}/participant_{}_their_secret_shares",
        DATA_DIR, participant_index
    )
}

pub fn get_public_key_file_name(participant_index: u32) -> String {
    format!("{}/participant_{}_pk.json", DATA_DIR, participant_index)
}

pub fn get_signers_file_name() -> String {
    format!("{}/signers.json", DATA_DIR)
}

pub fn get_partial_signature_file_name(participant_index: u32) -> String {
    format!(
        "{}/participant_{}_partial_signature.json",
        DATA_DIR, participant_index
    )
}

pub fn get_finalized_file_name() -> String {
    format!("{}/finalized.txt", DATA_DIR)
}

pub async fn delete_all_files(i: u32) -> Result<()> {
    if fs::metadata(get_signers_file_name()).await.is_ok() {
        fs::remove_file(get_signers_file_name()).await?;
    }

    if fs::metadata(get_partial_signature_file_name(i as u32))
        .await
        .is_ok()
    {
        fs::remove_file(get_partial_signature_file_name(i as u32)).await?;
    }

    if fs::metadata(get_public_key_file_name(i as u32))
        .await
        .is_ok()
    {
        fs::remove_file(get_public_key_file_name(i as u32)).await?;
    }

    if fs::metadata(get_their_secret_shares_file_name(i as u32))
        .await
        .is_ok()
    {
        fs::remove_file(get_their_secret_shares_file_name(i as u32)).await?;
    }

    if fs::metadata(get_published_participant_file_name(i as u32))
        
        .await
        .is_ok()
    {
        fs::remove_file(get_published_participant_file_name(i as u32)).await?;
    }
    
    if fs::metadata(get_finalized_file_name()).await.is_ok() {
        fs::remove_file(get_finalized_file_name()).await?;
    }

    Ok(())
}

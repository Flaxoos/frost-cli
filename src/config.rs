use std::time::Duration;

pub const SHARES: usize = 5;
pub const THRESHOLD: u32 = 3;

pub const MESSAGE: &[u8; 25] = b"Is it secret? is it safe?";
pub const CONTEXT: &[u8; 28] = b"Keep it secret, keep it safe";
pub const FINALIZED: &str = "finalized";
pub const HEART_BEAT: Duration = Duration::from_secs(1);

pub fn get_published_participant_file_name(participant_index: u32) -> String {
    format!("participant_{}.json", participant_index)
}

pub fn get_secret_shares_file_name(participant_index: u32) -> String {
    format!("participant_{}_their_secret_shares.json", participant_index)
}

pub fn get_public_key_file_name(participant_index: u32) -> String {
    format!("participant_{}_pk.json", participant_index)
}

pub fn get_signers_file_name() -> String {
    "signers.json".to_string()
}

pub fn get_partial_signature_file_name(participant_index: u32) -> String {
    format!("participant_{}_partial_signature.json", participant_index)
}

pub fn get_finalized_file_name() -> String {
    "finalized.json".to_string()
}



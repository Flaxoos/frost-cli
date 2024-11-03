use crate::comshare_serde::PublicCommitmentShareListWrapper;
use crate::config::{get_partial_signature_file_name, get_public_key_file_name, get_published_participant_file_name, get_secret_shares_file_name, get_final_signature_file_name, get_signers_file_name, SHARES, get_finalized_file_name, FINALIZED};
use crate::participant_serde::ParticipantWrapper;
use crate::public_key_serde::IndividualPublicKeyWrapper;
use crate::secret_share_serde::SecretShareWrapper;
use crate::signer_serde::SignerWrapper;
use crate::Result;
use frost_dalek::keygen::SecretShare;
use frost_dalek::precomputation::PublicCommitmentShareList;
use frost_dalek::signature::{PartialThresholdSignature, Signer, ThresholdSignature};
use frost_dalek::{generate_commitment_share_lists, IndividualPublicKey, Participant};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use crate::partial_sig_serde::PartialThresholdSignatureWrapper;

#[derive(Serialize, Deserialize)]
pub struct PublishedPublicKey {
    pub comshares: PublicCommitmentShareListWrapper,
    pub public_key: IndividualPublicKeyWrapper,
}

pub async fn publish_participant(participant: &Participant) -> Result<()> {
    let participant_index = participant.index;
    let data_path = get_published_participant_file_name(participant_index);

    tokio::fs::write(
        &data_path,
        serde_json::to_string(&ParticipantWrapper(participant.clone()))?,
    )
    .await?;
    println!("Participant {} saved to {}", participant_index, data_path);
    Ok(())
}

pub async fn publish_their_secret_shares(
    participant_index: u32,
    secret_shares: &Vec<SecretShare>,
) -> Result<()> {
    let data_path = get_secret_shares_file_name(participant_index);
    tokio::fs::write(
        &data_path,
        serde_json::to_string(&SecretShareWrapper(secret_shares.clone()))?,
    )
    .await?;
    println!(
        "Public data for participant {} saved to {}",
        participant_index, data_path
    );
    Ok(())
}

pub async fn publish_public_key(
    participant_index: u32,
    public_comshares: PublicCommitmentShareList,
    public_key: IndividualPublicKey,
) -> Result<()> {
    let data_path = get_public_key_file_name(participant_index);
    let published_public_key = PublishedPublicKey {
        comshares: PublicCommitmentShareListWrapper(public_comshares),
        public_key: IndividualPublicKeyWrapper(public_key),
    };
    tokio::fs::write(&data_path, serde_json::to_string(&published_public_key)?).await?;
    println!(
        "Public key for participant {} saved to {}",
        participant_index, data_path
    );
    Ok(())
}

pub async fn has_aggregation_commenced() -> bool {
    let data_path = get_signers_file_name();
    tokio::fs::metadata(&data_path).await.is_ok()
}

pub async fn notify_aggregation_commenced() -> Result<()> {
    // First create the file to notify other participants that the aggregation task has been taken on
    let data_path = get_signers_file_name();
    File::create(data_path)?;
    Ok(())
}

pub async fn publish_signers(signers: &[Signer]) -> Result<()> {
    if signers.is_empty() {
        todo!("Handle empty list of signers");
    }
    
    let data_path = get_signers_file_name();
    let signers_wrappers: Vec<SignerWrapper> =
        signers.into_iter().map(|x| SignerWrapper(*x)).collect();
    tokio::fs::write(&data_path, serde_json::to_string(&signers_wrappers)?).await?;
    println!("Signers saved to {}", data_path);
    Ok(())
}

pub async fn publish_partial_signature(
    participant_index: u32,
    partial_threshold_signature: PartialThresholdSignature
) -> Result<()> {
    let data_path = get_partial_signature_file_name(participant_index);
    tokio::fs::write(&data_path, serde_json::to_string(&PartialThresholdSignatureWrapper(partial_threshold_signature)).unwrap()).await.unwrap();
    println!("Partial signature for participant {} saved to {}", participant_index, data_path);
    Ok(())
}

pub async fn publish_finalized() -> Result<()> {
    let data_path = get_finalized_file_name();
    tokio::fs::write(&data_path, FINALIZED).await?;
    println!("Finalization confirmation saved to {}", data_path);
    Ok(())
}

pub async fn read_published_participant(participant_index: u32) -> Result<Participant> {
    let data_path = get_published_participant_file_name(participant_index);
    let json = tokio::fs::read_to_string(&data_path).await?;
    let participant_wrapper: ParticipantWrapper = serde_json::from_str(&json)?;
    Ok(participant_wrapper.0)
}

pub async fn read_published_secret_shares(participant_index: u32) -> Result<Vec<SecretShare>> {
    let data_path = get_secret_shares_file_name(participant_index);
    let json = tokio::fs::read_to_string(&data_path).await?;
    let secret_share_wrapper: SecretShareWrapper = serde_json::from_str(&json)?;
    Ok(secret_share_wrapper.0)
}

pub async fn read_published_public_key(participant_index: u32) -> Result<PublishedPublicKey> {
    let data_path = get_public_key_file_name(participant_index);
    let json = tokio::fs::read_to_string(&data_path).await?;
    let published_public_key: PublishedPublicKey = serde_json::from_str(&json)?;
    Ok(published_public_key)
}

pub async fn read_signers() -> Result<Vec<Signer>> {
    let data_path = get_signers_file_name();
    let json = tokio::fs::read_to_string(&data_path).await?;
    let signers_wrapper: Vec<SignerWrapper> = serde_json::from_str(&json)?;
    Ok(signers_wrapper.into_iter().map(|s| s.0).collect())
}

pub async fn read_partial_signature(participant_index: u32) -> Result<PartialThresholdSignature> {
    let data_path = get_partial_signature_file_name(participant_index);
    let json = tokio::fs::read_to_string(&data_path).await?;
    let partial_sig_wrapper: PartialThresholdSignatureWrapper = serde_json::from_str(&json)?;
    Ok(partial_sig_wrapper.0)
}

pub async fn read_finalized() -> Result<bool> {
    let data_path = get_finalized_file_name();
    let text = tokio::fs::read_to_string(&data_path).await?;
    Ok(text == FINALIZED)
}

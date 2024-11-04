use crate::comshare_serde::PublicCommitmentShareListWrapper;
use crate::config::{
    get_finalized_file_name, get_partial_signature_file_name, get_public_key_file_name,
    get_published_participant_file_name, get_their_secret_shares_file_name, get_signers_file_name,
    FINALIZED,
};
use crate::partial_sig_serde::PartialThresholdSignatureWrapper;
use crate::participant_serde::ParticipantWrapper;
use crate::public_key_serde::IndividualPublicKeyWrapper;
use crate::secret_share_serde::SecretShareWrapper;
use crate::signer_serde::SignerWrapper;
use crate::Result;
use frost_dalek::keygen::SecretShare;
use frost_dalek::precomputation::PublicCommitmentShareList;
use frost_dalek::signature::{PartialThresholdSignature, Signer};
use frost_dalek::{IndividualPublicKey, Participant};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Serialize, Deserialize)]
pub struct PublishedPublicKey {
    pub comshares: PublicCommitmentShareListWrapper,
    pub public_key: IndividualPublicKeyWrapper,
}

pub async fn publish_participant(participant: &Participant) -> Result<()> {
    let data_path = get_published_participant_file_name(participant.index);
    let wrapper = ParticipantWrapper(participant.clone());
    let serialized = bincode::serialize(&wrapper).unwrap();
    tokio::fs::write(&data_path, serialized).await?;
    debug!("Participant {} saved to {}", participant.index, data_path);
    Ok(())
}

pub async fn publish_their_secret_shares(
    participant_index: u32,
    secret_shares: &Vec<SecretShare>,
) -> Result<()> {
    debug!(
        "\t\tPublishing secret shares for participant {}",
        participant_index
    );
    let data_path = get_their_secret_shares_file_name(participant_index);
    let serialized = bincode::serialize(&SecretShareWrapper(secret_shares.clone())).unwrap();
    tokio::fs::write(&data_path, serialized).await?;
    debug!(
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
    debug!(
        "\t\tPublishing public key for participant {}",
        participant_index
    );
    let data_path = get_public_key_file_name(participant_index);
    let published_public_key = PublishedPublicKey {
        comshares: PublicCommitmentShareListWrapper(public_comshares),
        public_key: IndividualPublicKeyWrapper(public_key),
    };
    tokio::fs::write(&data_path, serde_json::to_string(&published_public_key)?).await?;
    debug!(
        "Public key for participant {} saved to {}",
        participant_index, data_path
    );
    Ok(())
}

pub async fn has_aggregation_commenced() -> bool {
    debug!("\t\tChecking if the aggregation task has been taken on");
    let data_path = get_signers_file_name();
    tokio::fs::metadata(&data_path).await.is_ok()
}

pub async fn notify_aggregation_commenced() -> Result<()> {
    debug!("\t\tNotifying other participants that the aggregation task has been taken on");
    // First create the file to notify other participants that the aggregation task has been taken on
    let data_path = get_signers_file_name();
    File::create(data_path)?;
    debug!("\t\tNotified other participants that the aggregation task has been taken on");
    Ok(())
}

pub async fn publish_signers(signers: &[Signer]) -> Result<()> {
    debug!("\t\tPublishing signers");
    if signers.is_empty() {
        todo!("Handle empty list of signers");
    }

    let data_path = get_signers_file_name();
    let signers_wrappers: Vec<SignerWrapper> = signers.iter().map(|x| SignerWrapper(*x)).collect();
    let serialized = bincode::serialize(&signers_wrappers).unwrap();
    tokio::fs::write(&data_path, serialized).await?;
    debug!("\t\tSigners saved to {}", data_path);
    Ok(())
}

pub async fn publish_partial_signature(
    participant_index: u32,
    partial_threshold_signature: PartialThresholdSignature,
) -> Result<()> {
    debug!(
        "\t\tPublishing partial signature for participant {}",
        participant_index
    );
    let data_path = get_partial_signature_file_name(participant_index);
    let json = serde_json::to_string(&PartialThresholdSignatureWrapper(
        partial_threshold_signature,
    ))?;
    tokio::fs::write(&data_path, json.clone()).await?;
    debug!(
        "Partial signature for participant {}, {} saved to {}",
        participant_index, json, data_path
    );
    Ok(())
}

pub async fn publish_finalized() -> Result<()> {
    debug!("\t\tPublishing finalization confirmation");
    let data_path = get_finalized_file_name();
    tokio::fs::write(&data_path, FINALIZED).await?;
    debug!("\t\tFinalization confirmation saved to {}", data_path);
    Ok(())
}
use tokio::fs;

pub async fn read_published_participant(participant_index: u32) -> Result<Option<Participant>> {
    let data_path = get_published_participant_file_name(participant_index);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let data = fs::read(&data_path).await?;
    let participant_wrapper: ParticipantWrapper = bincode::deserialize(&data)?;
    debug!("Read published participant {}", participant_index);
    Ok(Some(participant_wrapper.0))
}

pub async fn read_their_secret_shares(
    participant_index: u32,
) -> Result<Option<Vec<SecretShare>>> {
    debug!(
        "\t\tReading published secret shares for participant {}",
        participant_index
    );
    let data_path = get_their_secret_shares_file_name(participant_index);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let data = fs::read(&data_path).await?;
    if data.is_empty() {
        return Ok(Some(vec![]));
    }
    let secret_share_wrapper: SecretShareWrapper = bincode::deserialize(&data)?;
    debug!(
        "\t\tRead {} published secret shares for participant {}",
        secret_share_wrapper.0.len(), participant_index
    );
    Ok(Some(secret_share_wrapper.0))
}

pub async fn read_published_public_key(
    participant_index: u32,
) -> Result<Option<PublishedPublicKey>> {
    debug!(
        "\t\tReading published public key for participant {}",
        participant_index
    );
    let data_path = get_public_key_file_name(participant_index);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let json = fs::read_to_string(&data_path).await?;
    let published_public_key: PublishedPublicKey = serde_json::from_str(&json)?;
    debug!(
        "\t\tRead published public key for participant {}",
        participant_index
    );
    Ok(Some(published_public_key))
}

pub async fn read_signers() -> Result<Option<Vec<Signer>>> {
    debug!("\t\tReading signers");
    let data_path = get_signers_file_name();
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }

    let data = fs::read(&data_path).await?;
    if data.is_empty() {
        return Ok(Some(vec![]));
    }
    let signers_wrapper: Vec<SignerWrapper> = bincode::deserialize(&data)?;
    debug!("\t\tRead signers");
    Ok(Some(signers_wrapper.into_iter().map(|s| s.0).collect()))
}

pub async fn read_partial_signature(
    participant_index: u32,
) -> Result<Option<PartialThresholdSignature>> {
    debug!(
        "\t\tReading partial signature for participant {}",
        participant_index
    );
    let data_path = get_partial_signature_file_name(participant_index);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let json = fs::read_to_string(&data_path).await?;
    debug!(
        "\t\tRead raw partial signature for participant {}, {}",
        participant_index, json
    );
    let partial_sig_wrapper: PartialThresholdSignatureWrapper = serde_json::from_str(&json)?;
    debug!(
        "\t\tRead partial signature for participant {}",
        participant_index
    );
    Ok(Some(partial_sig_wrapper.0))
}

pub async fn read_finalized() -> Result<Option<bool>> {
    debug!("\t\tReading finalized status");
    let data_path = get_finalized_file_name();
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let text = fs::read_to_string(&data_path).await?;
    debug!("\t\tRead finalized status: {}", text);
    Ok(Some(text == FINALIZED))
}

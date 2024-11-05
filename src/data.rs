use crate::comshare_serde::PublicCommitmentShareListWrapper;
use crate::config::{
    get_finalized_file_name,
    get_partial_signature_file_name, get_public_key_file_name, get_published_participant_file_name,
    get_signers_file_name, get_their_secret_shares_file_name, FINALIZED,
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
use itertools::Itertools;
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::fs::File;

use fs2::FileExt;
use std::io;
use std::io::{Read, Write};

#[derive(Serialize, Deserialize)]
pub struct PublishedPublicKey {
    pub comshares: PublicCommitmentShareListWrapper,
    pub public_key: IndividualPublicKeyWrapper,
}

pub async fn publish_participant(participant: &Participant) -> Result<()> {
    let data_path = get_published_participant_file_name(participant.index).await;
    let wrapper = ParticipantWrapper(participant.clone());
    let serialized = bincode::serialize(&wrapper).unwrap();
    tokio::fs::write(&data_path, serialized).await?;
    info!("Participant {} saved to {}", participant.index, data_path);
    Ok(())
}

pub async fn publish_their_secret_shares(
    participant_index: u32,
    secret_shares: &Vec<SecretShare>,
) -> Result<()> {
    info!(
        "Publishing secret shares for participant {}",
        participant_index
    );

    // Prepare the data to write
    let mut buffer = Vec::new();
    for share in secret_shares {
        let serialized = bincode::serialize(&SecretShareWrapper(share.clone()))?;
        let length_prefix = (serialized.len() as u64).to_be_bytes();
        buffer.extend_from_slice(&length_prefix);
        buffer.extend_from_slice(&serialized);
    }

    // Lock, write, and unlock the file
    let data_path = get_their_secret_shares_file_name(participant_index).await;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&data_path)
        .await
        .and_then(|file| {
            Ok(async move {
                let mut file = file.into_std().await;
                file.lock_exclusive()?;
                file.write_all(&buffer)?;
                file.unlock()?;
                Ok::<(), io::Error>(())
            })
        })?
        .await?;

    info!(
        "Secret shares [{}] for participant {} saved to {}",
        secret_shares
            .iter()
            .map(|share| share.index.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        participant_index,
        data_path
    );
    Ok(())
}

pub async fn publish_public_key(
    participant_index: u32,
    public_comshares: PublicCommitmentShareList,
    public_key: IndividualPublicKey,
) -> Result<()> {
    info!(
        "Publishing public key for participant {}",
        participant_index
    );

    let data_path = get_public_key_file_name(participant_index).await;
    let published_public_key = PublishedPublicKey {
        comshares: PublicCommitmentShareListWrapper(public_comshares),
        public_key: IndividualPublicKeyWrapper(public_key),
    };
    tokio::fs::write(&data_path, serde_json::to_string(&published_public_key)?).await?;
    info!(
        "Public key for participant {} saved to {}",
        participant_index, data_path
    );
    Ok(())
}

pub async fn has_aggregation_commenced() -> bool {
    info!("Checking if the aggregation task has been taken on");

    let data_path = get_signers_file_name().await;
    tokio::fs::metadata(&data_path).await.is_ok()
}

pub async fn notify_aggregation_commenced() -> Result<()> {
    info!("Notifying other participants that the aggregation task has been taken on");
    // First create the file to notify other participants that the aggregation task has been taken on
    let data_path = get_signers_file_name().await;
    File::create(data_path).await?;
    info!("Notified other participants that the aggregation task has been taken on");
    Ok(())
}

pub async fn publish_signers(signers: &[Signer]) -> Result<()> {
    info!("Publishing signers");
    if signers.is_empty() {
        todo!("Handle empty list of signers");
    }

    let data_path = get_signers_file_name().await;
    let signers_wrappers: Vec<SignerWrapper> = signers.iter().map(|x| SignerWrapper(*x)).collect();
    let serialized = bincode::serialize(&signers_wrappers).unwrap();
    tokio::fs::write(&data_path, serialized).await?;
    info!("Signers saved to {}", data_path);
    Ok(())
}

pub async fn publish_partial_signature(
    participant_index: u32,
    partial_threshold_signature: PartialThresholdSignature,
) -> Result<()> {
    info!(
        "Publishing partial signature for participant {}",
        participant_index
    );

    let data_path = get_partial_signature_file_name(participant_index).await;
    let json = serde_json::to_string(&PartialThresholdSignatureWrapper(
        partial_threshold_signature,
    ))?;
    tokio::fs::write(&data_path, json.clone()).await?;
    info!(
        "Partial signature for participant {}, {} saved to {}",
        participant_index, json, data_path
    );
    Ok(())
}

pub async fn publish_finalized() -> Result<()> {
    info!("Publishing finalization confirmation");

    let data_path = get_finalized_file_name().await;
    tokio::fs::write(&data_path, FINALIZED).await?;
    info!("Finalization confirmation saved to {}", data_path);
    Ok(())
}

pub async fn read_published_participant(participant_index: u32) -> Result<Option<Participant>> {
    let data_path = get_published_participant_file_name(participant_index).await;
    info!("Reading published participant data from {}", data_path);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let data = fs::read(&data_path).await?;
    let participant_wrapper: ParticipantWrapper = bincode::deserialize(&data)?;
    info!("Read published participant {}", participant_index);
    Ok(Some(participant_wrapper.0))
}

pub async fn read_published_secret_shares(
    participant_index: u32,
) -> Result<Option<Vec<SecretShare>>> {
    let data_path = get_their_secret_shares_file_name(participant_index).await;
    info!("Reading published secret shares from {}", data_path);

    if !std::fs::metadata(&data_path).is_ok() {
        return Ok(None);
    }

    let mut file = std::fs::File::open(&data_path)?;
    let mut secret_shares = Vec::new();

    loop {
        let mut length_prefix = [0u8; 8];
        if file.read_exact(&mut length_prefix).is_err() {
            break; // End of file reached
        }

        let length = u64::from_be_bytes(length_prefix) as usize;
        let mut serialized_data = vec![0; length];
        file.read_exact(&mut serialized_data)?;

        let result = bincode::deserialize::<SecretShareWrapper>(&serialized_data);
        if let Ok(share_wrapper) = result {
            trace!(
                "Deserialized secret share index {} from {}",
                share_wrapper.0.index,
                data_path
            );
            secret_shares.push(share_wrapper.0);
        } else {
            warn!(
                "Failed to deserialize secret share from {}: {:?}",
                data_path,
                result.err()
            );
            return Ok(None);
        }
    }

    info!(
        "Secret shares [{}] for participant {} read from {}",
        secret_shares.iter().map(|x| x.index).join(", "),
        participant_index,
        data_path
    );

    Ok(Some(secret_shares))
}

pub async fn read_published_public_key(
    participant_index: u32,
) -> Result<Option<PublishedPublicKey>> {
    let data_path = get_public_key_file_name(participant_index).await;
    info!("Reading published public key from {}", data_path);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let json = fs::read_to_string(&data_path).await?;
    let published_public_key: PublishedPublicKey = serde_json::from_str(&json)?;
    info!(
        "Read published public key for participant {} from {}",
        participant_index, data_path
    );
    Ok(Some(published_public_key))
}

pub async fn read_signers() -> Result<Option<Vec<Signer>>> {
    let data_path = get_signers_file_name().await;
    info!("Reading signers from {}", data_path);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let data = fs::read(&data_path).await?;
    if data.is_empty() {
        return Ok(Some(vec![]));
    }
    let signers_wrapper: Vec<SignerWrapper> = bincode::deserialize(&data)?;
    info!("Read signers from {}", data_path);
    Ok(Some(signers_wrapper.into_iter().map(|s| s.0).collect()))
}

pub async fn read_partial_signature(
    participant_index: u32,
) -> Result<Option<PartialThresholdSignature>> {
    let data_path = get_partial_signature_file_name(participant_index).await;
    info!("Reading partial signature from {}", data_path);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let json = fs::read_to_string(&data_path).await?;
    info!(
        "Read raw partial signature for participant {} from {}",
        participant_index, data_path
    );
    let partial_sig_wrapper: PartialThresholdSignatureWrapper = serde_json::from_str(&json)?;
    info!(
        "Read partial signature for participant {} from {}",
        participant_index, data_path
    );
    Ok(Some(partial_sig_wrapper.0))
}

pub async fn read_finalized() -> Result<Option<bool>> {
    let data_path = get_finalized_file_name().await;
    info!("Reading finalized status from {}", data_path);
    if !fs::metadata(&data_path).await.is_ok() {
        return Ok(None);
    }
    let text = fs::read_to_string(&data_path).await?;
    info!("Read finalized status from {}: {}", data_path, text);
    Ok(Some(text == FINALIZED))
}

mod commands;
mod comshare_serde;
mod config;
mod partial_sig_serde;
mod participant_serde;
mod public_key_serde;
mod publish;
mod secret_share_serde;
mod signer_serde;

use crate::commands::{Cli, Commands};
use crate::config::{delete_all_files, CONTEXT, HEART_BEAT, MESSAGE, SHARES, THRESHOLD};
use crate::publish::{
    has_aggregation_commenced, notify_aggregation_commenced, publish_finalized,
    publish_partial_signature, publish_participant, publish_public_key, publish_signers,
    publish_their_secret_shares, read_finalized, read_partial_signature,
    read_published_participant, read_published_public_key, read_signers, read_their_secret_shares,
    PublishedPublicKey,
};
use clap::Parser;
use curve25519_dalek::ristretto::RistrettoPoint;
use frost_dalek::keygen::{Coefficients, SecretShare};
use frost_dalek::precomputation::{PublicCommitmentShareList, SecretCommitmentShareList};
use frost_dalek::signature::{Finalized, Initial, PartialThresholdSignature, SecretKey, Signer};
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, GroupKey,
    IndividualPublicKey, Parameters, Participant, SignatureAggregator,
};
use futures::stream::{FuturesUnordered, StreamExt};
use itertools::Itertools;
use log::{debug, error, info};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;
use thiserror::Error;
use tokio::task;
use tokio::time::sleep;
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error occurred: {0}")]
    IO(#[from] io::Error),

    #[error("Serialization/Deserialization error: {0:?}")]
    Serde(#[from] serde_json::error::Error),

    #[error("Bincode error: {0:?}")]
    Bincode(#[from] bincode::Error),

    #[error("Misbehaving participant(s) detected: {0:?}")]
    MisbehavingDkg(Vec<u32>),

    #[error("Misbehaving participant(s) detected: {0:?}")]
    MisbehavingFinalization(HashMap<u32, &'static str>),

    #[error("Insufficient number of secret shares provided")]
    InsufficientSecretShares,

    #[error("Failed to complete DKG process")]
    DkgFinishFailure,

    #[error("Task join error: {0}")]
    Task(#[from] task::JoinError),

    #[error("Signing error: {0}")]
    Signing(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match match cli.command {
        Commands::StartSession { participant_index } => {
            start_session(
                participant_index,
                Parameters {
                    n: SHARES as u32,
                    t: THRESHOLD,
                },
            )
            .await
        }
    } {
        Ok(()) => (),
        Err(e) => {
            error!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn start_session(participant_index: u32, parameters: Parameters) -> Result<()> {
    delete_all_files(participant_index).await?;
    info!("Starting session for participant {}", participant_index);

    let (participant, coefficients) = create_participant(participant_index, &parameters);

    publish_participant(&participant).await?;

    interactive_cli_loop(participant, coefficients, parameters).await?;

    info!("Session complete for participant {}", participant_index);
    Ok(())
}

fn create_participant(
    participant_index: u32,
    parameters: &Parameters,
) -> (Participant, Coefficients) {
    info!("Creating participant {}", participant_index);

    let (participant, coefficients) = Participant::new(parameters, participant_index);

    (participant, coefficients)
}

async fn interactive_cli_loop(
    participant: Participant,
    participant_coefficients: Coefficients,
    parameters: Parameters,
) -> Result<()> {
    let participant_index = participant.index;

    info!("Starting DKG for participant {}", participant_index);
    let dkg = task::spawn(generate_distributed_key(
        participant,
        participant_coefficients,
        parameters,
    ));

    loop {
        print!(
            "> Press any key when you are ready to sign, or type 'help' or 'exit' to continue: "
        );
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
        let input = input.trim();

        match input {
            "help" => {
                println!("Available commands:\n  - Press any key to sign\n  - Type 'exit' to end the session\n  - Type 'help' to show this message again");
            }
            "exit" => {
                println!("Ending session.");
                break;
            }
            _ => {
                info!("Checking if DKG is finished");
                if dkg.is_finished() {
                    let (gk, sk) = dkg.await??;
                    let (public_comshares, mut secret_comshares) =
                        generate_commitment_share_lists(&mut OsRng, participant_index, 1);
                    let pk: IndividualPublicKey = (&sk).into();
                    info!(
                        "Publishing public key:\np_i: {}\npk: {}\ncomshares: {}",
                        participant_index,
                        hex::encode(public_key_to_string(&pk.share)),
                        public_comshares_to_string(&public_comshares)
                    );
                    task::spawn(publish_public_key(participant_index, public_comshares, pk));
                    let mut aggregator: Option<SignatureAggregator<Initial>> = None;
                    if !has_aggregation_commenced().await {
                        // Then i am the aggregator
                        aggregator = Some(commence_aggregation(parameters, gk).await?);
                    }

                    let signers = wait_for_signers(parameters.t).await?;
                    info!(
                        "Computing message hash: context {}, message {}",
                        hex::encode(&CONTEXT[..]),
                        hex::encode(&MESSAGE[..])
                    );
                    let message_hash = compute_message_hash(&CONTEXT[..], &MESSAGE[..]);

                    info!("Signing message: participant index {}, message hash {}, group key {}, secret shares {}, my commitment share index {} signers {}",
                        participant_index,
                        hex::encode(&message_hash[..]),
                        hex::encode(&gk.to_bytes()),
                        secret_comshares_to_string(&secret_comshares),
                        0,
                        signers.len(),
                    );
                    sign_message(
                        participant_index,
                        message_hash,
                        sk,
                        gk,
                        &mut secret_comshares,
                        signers.as_slice(),
                    )
                    .await?;
                    info!("Message signed.");

                    if let Some(mut aggregator) = aggregator {
                        // Because i am the aggregator, finalize the aggregation
                        for sig in collect_partial_signatures(parameters).await? {
                            aggregator.include_partial_signature(sig);
                        }

                        let aggregator = finalize_aggregation(parameters.t, aggregator).await?;

                        let sig = aggregator
                            .aggregate()
                            .map_err(|e| Error::MisbehavingFinalization(e))?;
                        sig.verify(&gk, &message_hash)
                            .map_err(|_| Error::MisbehavingFinalization(HashMap::new()))?;
                        publish_finalized().await?;
                    }

                    wait_for_finalization().await?;
                    print!("Finalized!");
                    break;
                } else {
                    info!("Not enough participants are ready for signing.");
                }
            }
        }
    }
    Ok(())
}
async fn wait_todo(){
    sleep(Duration::from_secs(0)).await;
}
async fn generate_distributed_key<'a>(
    participant: Participant,
    participant_coefficients: Coefficients,
    parameters: Parameters,
) -> Result<(GroupKey, SecretKey)> {
    let participant_index = participant.index;
    
    let mut other_participants = collect_other_participants(participant_index, parameters.n).await?;

    wait_todo().await;
    // No need to do verification as it is already done in the DKG round 1
    info!(
        "DKG round 1 starting. other participants: {}",
        other_participants
            .iter()
            .map(|p| p.index.to_string())
            .map(|x| x.to_string())
            .join(", ")
    );
    let dkg = DistributedKeyGeneration::new(
        &parameters,
        &participant_index,
        &participant_coefficients,
        &mut other_participants,
    )
    .map_err(|e| Error::MisbehavingDkg(e))?;

    wait_todo().await;
    
    if let Ok(their_secret_shares) = dkg.their_secret_shares() {
        if their_secret_shares.is_empty() {
            panic!("No other participants")
        }
        info!(
            "Publishing their secret shares: [{}]",
            their_secret_shares
                .iter()
                .map(|share| share.index.to_string())
                .join(", ")
        );
        publish_their_secret_shares(participant_index, their_secret_shares).await?;
    };

    wait_todo().await;
    let my_secret_shares = collect_my_secret_shares(participant_index, parameters.n).await?;
    
    info!(
        "DKG round 2 Starting. My secret shares: [{}]",
        my_secret_shares
            .iter()
            .map(|share| share.index.to_string())
            .join(", ")
    );

    let dkg = dkg
        .to_round_two(my_secret_shares)
        .map_err(|_| Error::InsufficientSecretShares)?;
    let pk = participant
        .public_key()
        .expect("Participant has no public key, this shouldn't happen at this point");
    info!(
        "Finishing DKG with public key: {}",
        public_key_to_string(pk)
    );
    let (group_key, secret_key) = dkg.finish(pk).map_err(|_| Error::DkgFinishFailure)?;
    info!("Resulting group key: {}", hex::encode(group_key.to_bytes()));
    Ok((group_key, secret_key))
}

async fn wait_for_signers(t: u32) -> Result<Vec<Signer>> {
    info!("Waiting for signers");
    loop {
        match read_signers().await? {
            Some(signers) if (signers.len() as u32) >= t => {
                info!("Collected sufficient signers");
                return Ok(signers);
            }
            _ => {
                debug!("No or insufficient signers collected, retrying...");
                sleep(HEART_BEAT).await;
            }
        }
    }
}

async fn wait_for_finalization() -> Result<()> {
    info!("Waiting for finalization");
    loop {
        match read_finalized().await? {
            Some(true) => {
                info!("Finalization completed");
                return Ok(());
            }
            Some(false) | None => {
                // Finalization file not yet indicating true, or not available; retry after sleep
                debug!("Finalization not yet complete, retrying...");
                sleep(HEART_BEAT).await;
            }
        }
    }
}

async fn collect_other_participants(participant_index: u32, n: u32) -> Result<Vec<Participant>> {
    info!("Collecting other participants");

    let mut tasks = vec![];

    for i in 1..=n {
        if i != participant_index {
            let handle = task::spawn(async move {
                info!("Waiting for participant {}", i);
                loop {
                    match read_published_participant(i).await? {
                        Some(participant) => {
                            info!("Collected participant {}", i);
                            return Ok(participant); // Return the participant if found
                        }
                        None => {
                            debug!("Participant {} not found, retrying...", i);
                            sleep(HEART_BEAT).await;
                        }
                    }
                }
            });

            tasks.push(handle);
        }
    }

    // Await all tasks and collect the results
    let mut collector = vec![];
    for task in tasks {
        match task.await? {
            Ok(participant) => {
                collector.push(participant);
            }
            Err(e) => {
                error!("Failed to read participant: {}", e);
                return Err(e);
            }
        }
    }

    Ok(collector)
}

async fn collect_my_secret_shares(participant_index: u32, n: u32) -> Result<Vec<SecretShare>> {
    let mut tasks = vec![];

    for i in 1..=n {
        if i != participant_index {
            let handle = task::spawn(async move {
                info!("Waiting for secret shares of participant {}", i);
                loop {
                    match read_their_secret_shares(i).await? {
                        Some(secret_shares) if (secret_shares.len() as u32) == n - 1 => {
                            // Filter to get only the shares for the participant_index
                            let my_secret_shares: Vec<SecretShare> = secret_shares
                                .into_iter()
                                .filter(|share| share.index == participant_index)
                                .collect();
                            info!("Collected secret shares for participant {}", i);
                            return Ok(my_secret_shares);
                        }
                        _ => {
                            debug!("Secret shares of participant {} not found, retrying...", i);
                            sleep(HEART_BEAT).await;
                        }
                    }
                }
            });

            tasks.push(handle);
        }
    }

    // Await all tasks and collect results
    let mut collector = vec![];
    for task in tasks {
        match task.await? {
            Ok(my_secret_shares) => collector.extend(my_secret_shares),
            Err(e) => return Err(e), // Return the error if any task fails
        }
    }

    Ok(collector)
}

async fn collect_published_pks(parameters: Parameters) -> Result<Vec<PublishedPublicKey>> {
    let mut tasks = FuturesUnordered::new();

    // Spawn a task for each participant's public key
    for i in 1..=parameters.n {
        let handle = task::spawn(async move {
            info!("Waiting for published public key of participant {}", i);
            loop {
                match read_published_public_key(i).await? {
                    Some(public_key) => {
                        info!("Collected published public key for participant {}", i);
                        return Ok(public_key);
                    }
                    None => {
                        debug!(
                            "Published public key of participant {} not found, retrying...",
                            i
                        );
                        sleep(HEART_BEAT).await;
                    }
                }
            }
        });
        tasks.push(handle);
    }

    // Collect results as each task completes
    let mut collector: Vec<Result<PublishedPublicKey>> = vec![];
    while (collector.len() as u32) < parameters.t {
        match tasks.next().await {
            Some(result) => collector.push(result?),
            None => break,
        }
    }
    //todo: print errors
    Ok(collector.into_iter().filter_map(Result::ok).collect())
}

async fn collect_partial_signatures(
    parameters: Parameters,
) -> Result<Vec<PartialThresholdSignature>> {
    let mut tasks = FuturesUnordered::new();

    // Spawn a task for each participant's public key
    for i in 1..=parameters.n {
        let handle = task::spawn(async move {
            info!("Waiting for partial signature of participant {}", i);
            loop {
                match read_partial_signature(i).await? {
                    Some(partial_sig) => {
                        info!("Collected partial signature for participant {}", i);
                        return Ok(partial_sig);
                    }
                    None => {
                        debug!(
                            "Partial signature of participant {} not found, retrying...",
                            i
                        );
                        sleep(HEART_BEAT).await;
                    }
                }
            }
        });
        tasks.push(handle);
    }

    // Collect results as each task completes
    let mut collector: Vec<Result<PartialThresholdSignature>> = vec![];
    while (collector.len() as u32) < parameters.t {
        match tasks.next().await {
            Some(result) => collector.push(result?),
            None => break,
        }
    }
    //todo: print errors
    Ok(collector.into_iter().filter_map(Result::ok).collect())
}

async fn sign_message(
    participant_index: u32,
    message_hash: [u8; 64],
    secret_key: SecretKey,
    group_key: GroupKey,
    secret_shares: &mut SecretCommitmentShareList,
    signers: &[Signer],
) -> Result<()> {
    info!("Signing message as participant {}", participant_index);
    info!("Signing details: Participant index {}, message hash {}, group key {}, secret shares {}, my commitment share index {} signers {}",
        participant_index,
        hex::encode(message_hash),
        hex::encode(group_key.to_bytes()),
        secret_comshares_to_string(secret_shares),
        0,
        signers.len()
    );
    let partial = secret_key
        .sign(&message_hash, &group_key, secret_shares, 0, signers)
        .map_err(|e| Error::Signing(e))?;
    info!(
        "Publishing partial signature for participant {}",
        participant_index
    );
    publish_partial_signature(participant_index, partial).await?;
    Ok(())
}

async fn commence_aggregation<'a>(
    parameters: Parameters,
    group_key: GroupKey,
) -> Result<SignatureAggregator<Initial<'a>>> {
    info!("Commencing aggregation");
    notify_aggregation_commenced().await?;

    info!(
        "Collecting signers: group key {}, context {}, message {}",
        hex::encode(group_key.to_bytes()),
        hex::encode(&CONTEXT[..]),
        hex::encode(&MESSAGE[..])
    );
    let mut aggregator =
        SignatureAggregator::new(parameters, group_key, &CONTEXT[..], &MESSAGE[..]);

    let published_pks = collect_published_pks(parameters).await?;

    published_pks.into_iter().for_each(|ppk| {
        let participant_index = ppk.public_key.0.index;
        info!(
            "Including participant signer {} in aggregation",
            participant_index
        );
        aggregator.include_signer(
            participant_index,
            ppk.comshares.0.commitments[0],
            ppk.public_key.0,
        );
    });

    publish_signers(aggregator.get_signers()).await?;
    Ok(aggregator)
}

async fn finalize_aggregation<'a>(
    t: u32,
    aggregator: SignatureAggregator<Initial<'a>>,
) -> Result<SignatureAggregator<Finalized>> {
    info!("{}: Finalizing aggregation", t);
    loop {
        let remaining = aggregator.get_remaining_signers();
        if remaining.is_empty() {
            info!("{}: All signers have signed, finalizing", t);
            let finalized = aggregator
                .finalize()
                .expect("Finalize called before sufficient signers have signed");
            return Ok(finalized);
        } else {
            info!(
                "{}: Still waiting for {} signers to contribute: [{}]",
                t,
                remaining.len(),
                remaining
                    .iter()
                    .map(|x| x.participant_index.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            sleep(HEART_BEAT).await;
        }
    }
}

fn secret_comshares_to_string(s: &SecretCommitmentShareList) -> String {
    s.commitments
        .iter()
        .map(|x| {
            let (a, b) = x.publish();
            format!(
                "{},{}",
                hex::encode(a.compress().to_bytes()),
                hex::encode(b.compress().to_bytes())
            )
        })
        .join(", ")
}

fn public_comshares_to_string(s: &PublicCommitmentShareList) -> String {
    s.commitments
        .iter()
        .map(|(a, b)| {
            format!(
                "{},{}",
                hex::encode(a.compress().to_bytes()),
                hex::encode(b.compress().to_bytes())
            )
        })
        .join(", ")
}

fn public_key_to_string(pk: &RistrettoPoint) -> String {
    hex::encode(pk.compress().to_bytes())
}

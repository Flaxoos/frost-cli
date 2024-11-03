mod commands;
mod comshare_serde;
mod config;
mod partial_sig_serde;
mod participant_serde;
mod public_key_serde;
mod publish;
mod secret_share_serde;
mod signer_serde;

use crate::commands::{Cli, Commands, InteractiveCommands};
use crate::config::{CONTEXT, HEART_BEAT, MESSAGE, SHARES, THRESHOLD};
use crate::publish::{
    has_aggregation_commenced, notify_aggregation_commenced, publish_finalized,
    publish_partial_signature, publish_participant, publish_public_key, publish_signers,
    publish_their_secret_shares, read_finalized, read_published_participant,
    read_published_public_key, read_published_secret_shares, read_signers, PublishedPublicKey,
};
use clap::{Parser, Subcommand};
use frost_dalek::keygen::{Coefficients, SecretShare};
use frost_dalek::precomputation::SecretCommitmentShareList;
use frost_dalek::signature::{Finalized, Initial, SecretKey, Signer};
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, GroupKey,
    Parameters, Participant, SignatureAggregator,
};
use futures::stream::{FuturesUnordered, StreamExt};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::io::{self, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::task;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error occurred: {0}")]
    IO(#[from] io::Error),

    #[error("Serialization/Deserialization error: {0:?}")]
    Serde(#[from] serde_json::error::Error),

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
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn start_session(participant_index: u32, parameters: Parameters) -> Result<()> {
    println!("Starting session for participant {}", participant_index);

    let (participant, coefficients) = create_participant(participant_index, &parameters);

    publish_participant(&participant).await?;

    interactive_cli_loop(participant, coefficients, parameters).await?;

    println!("Session complete for participant {}", participant_index);
    Ok(())
}

fn create_participant(
    participant_index: u32,
    parameters: &Parameters,
) -> (Participant, Coefficients) {
    println!("Creating participant {}", participant_index);

    let (participant, coefficients) = Participant::new(parameters, participant_index);

    (participant, coefficients)
}

async fn interactive_cli_loop(
    participant: Participant,
    participant_coefficients: Coefficients,
    parameters: Parameters,
) -> Result<()> {
    let participant_index = participant.index;
    println!(
        "Interactive session started for participant {}",
        participant_index
    );

    let dkg = task::spawn(generate_distributed_key(
        participant,
        participant_coefficients,
        parameters,
    ));

    // let ready_to_sign = task::spawn();

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        // Read input from user
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
        let input = input.trim();
        match InteractiveCommands::try_parse_from(input.split_whitespace()) {
            Ok(command) => match command {
                InteractiveCommands::Sign => {
                    if dkg.is_finished() {
                        let (gk, sk) = dkg.await??;
                        let (public_comshares, mut secret_comshares) =
                            generate_commitment_share_lists(&mut OsRng, participant_index, SHARES);
                        task::spawn(publish_public_key(
                            participant_index,
                            public_comshares,
                            sk.to_public(),
                        ));

                        let mut aggregator: Option<SignatureAggregator<Initial>> = None;
                        if !has_aggregation_commenced().await {
                            // Then i am the aggregator
                            aggregator = Some(commence_aggregation(parameters, gk).await?);
                        }

                        let signers = wait_for_signers().await?;
                        let message_hash = compute_message_hash(&CONTEXT[..], &MESSAGE[..]);
                        sign_message(
                            participant_index,
                            message_hash,
                            sk,
                            gk,
                            &mut secret_comshares,
                            signers.as_slice(),
                        )
                        .await?;
                        println!("Message signed.");

                        if let Some(aggregator) = aggregator {
                            // Because i am the aggregator, finalize the aggregation
                            let aggregator = finalize_aggregation(parameters.t, aggregator).await?;
                            let sig = aggregator
                                .aggregate()
                                .map_err(|e| Error::MisbehavingFinalization(e))?;
                            sig.verify(&gk, &message_hash)
                                .map_err(|e| Error::MisbehavingFinalization(HashMap::new()))?;
                            publish_finalized().await?;
                        }
                        println!("Waiting for finalization");
                        wait_for_finalization().await?;
                        print!("Finalized!");
                        break;
                    } else {
                        println!("Not enough participants are ready for signing.");
                    }
                }
                InteractiveCommands::Help => {
                    println!("Available commands:\n  sign -- Sign a message\n  help -- Show this help message\n  exit -- End the session");
                }
                InteractiveCommands::Exit => {
                    println!("Ending session for participant {}", participant_index);
                    ()
                }
            },
            Err(_) => println!("Invalid command. Type 'help' for a list of available commands."),
        }
    }
    Ok(())
}

async fn generate_distributed_key<'a>(
    participant: Participant,
    participant_coefficients: Coefficients,
    parameters: Parameters,
) -> Result<(GroupKey, SecretKey)> {
    let participant_index = participant.index;
    // Spawn async tasks for collecting participants and secret shares
    let participants_handle =
        task::spawn(wait_for_participants(participant_index, parameters.clone()));
    let my_secret_shares_handle = task::spawn(wait_for_my_secret_shares(
        participant_index,
        parameters.clone(),
    ));

    // Await the results of both tasks
    let mut other_participants = participants_handle.await??;

    // No need to do verification as it is already done in the DKG round 1
    let dkg = DistributedKeyGeneration::new(
        &parameters,
        &participant_index,
        &participant_coefficients,
        &mut other_participants,
    )
    .map_err(|e| Error::MisbehavingDkg(e))?;

    if let Ok(their_secret_shares) = dkg.their_secret_shares() {
        publish_their_secret_shares(participant_index, their_secret_shares).await?;
    };

    let my_secret_shares = my_secret_shares_handle.await??;

    let dkg = dkg
        .to_round_two(my_secret_shares)
        .map_err(|_| Error::InsufficientSecretShares)?;
    let (group_key, secret_key) = dkg
        .finish(
            participant
                .public_key()
                .expect("Participant has no public key, this shouldn't happen at this point"),
        )
        .map_err(|_| Error::DkgFinishFailure)?;

    Ok((group_key, secret_key))
}

async fn wait_for_participants(
    participant_index: u32,
    parameters: Parameters,
) -> Result<Vec<Participant>> {
    let collected = Arc::new(AtomicBool::new(false));
    let collected_clone = Arc::clone(&collected);

    let mut collector = vec![];
    while !collected_clone.load(Ordering::Relaxed) {
        collect_other_participants(participant_index, &mut collector, parameters.n).await;
        collected_clone.store(
            collector.len() as u32 == (parameters.n - 1),
            Ordering::Relaxed,
        );

        tokio::time::sleep(HEART_BEAT).await;
    }

    println!("{}: Collected other participants", participant_index);
    Ok(collector)
}

async fn wait_for_my_secret_shares(
    participant_index: u32,
    parameters: Parameters,
) -> Result<Vec<SecretShare>> {
    let collected = Arc::new(AtomicBool::new(false));
    let collected_clone = Arc::clone(&collected);

    let mut collector = vec![];
    while !collected_clone.load(Ordering::Relaxed) {
        collect_my_secret_shares(participant_index, &mut collector, parameters.n).await;
        collected_clone.store(
            collector.len() as u32 == (parameters.n - 1),
            Ordering::Relaxed,
        );

        tokio::time::sleep(HEART_BEAT).await;
    }

    println!("{}: Collected others' secret shares", participant_index);
    Ok(collector)
}

async fn wait_for_signers() -> Result<Vec<Signer>> {
    let collected = Arc::new(AtomicBool::new(false));
    let collected_clone = Arc::clone(&collected);

    let mut collector = vec![];
    while !collected_clone.load(Ordering::Relaxed) {
        let signers = read_signers().await;
        if signers.is_ok() {
            collector = signers.unwrap();
            collected_clone.store(true, Ordering::Relaxed);
        }
        tokio::time::sleep(HEART_BEAT).await;
    }
    Ok(collector)
}

async fn wait_for_finalization() -> Result<()> {
    let collected = Arc::new(AtomicBool::new(false));
    let collected_clone = Arc::clone(&collected);

    while !collected_clone.load(Ordering::Relaxed) {
        let finalized = read_finalized().await;
        if finalized.is_ok() && finalized? {
            break;
        }
        tokio::time::sleep(HEART_BEAT).await;
    }
    Ok(())
}

async fn get_participant_published_public_key(
    participant_index: u32,
) -> Result<PublishedPublicKey> {
    loop {
        match read_published_public_key(participant_index).await {
            Ok(ppk) => return Ok(ppk),
            Err(e) => {
                if let Error::IO(io) = e {
                    if io.kind() == ErrorKind::NotFound {
                        tokio::time::sleep(HEART_BEAT).await;
                        continue;
                    }
                } else {
                    eprintln!("Failed to read comshares {}: {}", participant_index, e);
                    return Err(e);
                }
            }
        }
    }
}

async fn collect_other_participants(
    participant_index: u32,
    collector: &mut Vec<Participant>,
    n: u32,
) {
    for i in 0..n {
        if i != participant_index {
            if let Ok(published_participant) = read_published_participant(i).await {
                collector.push(published_participant)
            }
        }
    }
}

async fn collect_my_secret_shares(
    participant_index: u32,
    collector: &mut Vec<SecretShare>,
    n: u32,
) {
    for i in 0..n {
        if i != participant_index {
            if let Ok(their_secret_shares) = read_published_secret_shares(i).await {
                let my_secret_shares: Vec<SecretShare> = their_secret_shares
                    .iter()
                    .filter(|x| x.index == participant_index)
                    .map(|x| x.clone())
                    .collect();
                collector.extend(my_secret_shares);
            }
        }
    }
}

async fn collect_published_pks(parameters: Parameters) -> Result<Vec<PublishedPublicKey>> {
    let mut futures = FuturesUnordered::new();

    // Spawn `n` tasks and add them to FuturesUnordered
    for i in 1..=parameters.n + 1 {
        futures.push(task::spawn(get_participant_published_public_key(i)));
    }
    let mut collector: Vec<PublishedPublicKey> = vec![];
    // Collect the first `x` results
    while (collector.len() as u32) < parameters.t {
        if let Some(result) = futures.next().await {
            match result {
                Ok(comshare) => collector.push(comshare?),
                Err(e) => eprintln!("Task failed: {:?}", e), // Log any task failure
            }
        } else {
            break; // No more results to process
        }
    }
    Ok(collector)
}

async fn sign_message(
    participant_index: u32,
    message_hash: [u8; 64],
    secret_key: SecretKey,
    group_key: GroupKey,
    secret_shares: &mut SecretCommitmentShareList,
    signers: &[Signer],
) -> Result<()> {
    println!("Signing message as participant {}", participant_index);
    let partial = secret_key
        .sign(&message_hash, &group_key, secret_shares, 0, signers)
        .map_err(|e| Error::Signing(e))?;
    publish_partial_signature(participant_index, partial).await?;
    Ok(())
}

async fn commence_aggregation<'a>(
    parameters: Parameters,
    group_key: GroupKey,
) -> Result<SignatureAggregator<Initial<'a>>> {
    notify_aggregation_commenced().await?;

    let mut aggregator =
        SignatureAggregator::new(parameters, group_key, &CONTEXT[..], &MESSAGE[..]);

    let published_pks = collect_published_pks(parameters).await?;

    published_pks.into_iter().enumerate().for_each(|(i, ppk)| {
        aggregator.include_signer(i as u32, ppk.comshares.0.commitments[0], ppk.public_key.0);
    });

    publish_signers(aggregator.get_signers()).await?;
    Ok(aggregator)
}

async fn finalize_aggregation<'a>(
    t: u32,
    aggregator: SignatureAggregator<Initial<'a>>,
) -> Result<SignatureAggregator<Finalized>> {
    loop {
        let remaining = aggregator.get_remaining_signers();
        if remaining.is_empty() {
            let finalized = aggregator
                .finalize()
                .expect("Finalize called before sufficient signers have signed");
            return Ok(finalized);
        } else {
            println!(
                "{}: Waiting for {} signers to contribute: [{}]",
                t,
                remaining.len(),
                remaining
                    .iter()
                    .map(|x| x.participant_index.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            tokio::time::sleep(HEART_BEAT).await;
        }
    }
}

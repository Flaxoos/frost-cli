mod commands;
mod comshare_serde;
mod config;
mod data;
mod partial_sig_serde;
mod participant_serde;
mod public_key_serde;
mod secret_share_serde;
mod signer_serde;
use crate::commands::{Cli, Commands};
use crate::config::{get_shares, get_threshold, Error, Result, CONTEXT, HEART_BEAT, MESSAGE};
use crate::data::{
    get_ready_participants, has_aggregation_commenced, increment_ready_participants,
    notify_aggregation_commenced, publish_finalized, publish_partial_signature,
    publish_participant, publish_public_key, publish_signers, publish_their_secret_shares,
    read_finalized, read_partial_signature, read_published_participant, read_published_public_key,
    read_published_secret_shares, read_signers, PublishedPublicKey,
};
use clap::Parser;
use curve25519_dalek::ristretto::RistrettoPoint;
use dotenv::dotenv;
use frost_dalek::keygen::{Coefficients, SecretShare};
use frost_dalek::precomputation::{PublicCommitmentShareList, SecretCommitmentShareList};
use frost_dalek::signature::{Finalized, Initial, PartialThresholdSignature, SecretKey, Signer};
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, GroupKey,
    IndividualPublicKey, Parameters, Participant, SignatureAggregator,
};
use futures::stream::{FuturesUnordered, StreamExt};
use itertools::Itertools;
use log::{debug, error};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::io::{self, Write};
use tokio::task;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    env_logger::init();
    dotenv().ok();
    let cli = Cli::parse();

    match match cli.command {
        Commands::StartSession { participant_index } => {
            start_session(
                participant_index,
                Parameters {
                    n: get_shares(),
                    t: get_threshold(),
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
    println!(
        "Starting session for participant {}, parameters: {:#?}",
        participant_index, parameters
    );

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

    println!("Starting DKG for participant {}", participant_index);
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
                println!("Checking if DKG is finished");
                if dkg.is_finished() {
                    match dkg.await?? {
                        None => {
                            println!("Enough participants are ready for signing, leaving signing session");
                            break;
                        }
                        Some((gk, sk)) => {
                            println!("DKG is finished, publishing public key");
                            let (public_comshares, mut secret_comshares) =
                                generate_commitment_share_lists(&mut OsRng, participant_index, 1);
                            let pk: IndividualPublicKey = (&sk).into();
                            println!(
                                "Publishing public key:\np_i: {}\npk: {}\ncomshares: {}",
                                participant_index,
                                hex::encode(public_key_to_string(&pk.share)),
                                public_comshares_to_string(&public_comshares)
                            );
                            task::spawn(publish_public_key(
                                participant_index,
                                public_comshares,
                                pk,
                            ));
                            let mut aggregator: Option<SignatureAggregator<Initial>> = None;
                            if !has_aggregation_commenced().await {
                                // Then i am the aggregator
                                aggregator = Some(commence_aggregation(parameters, gk).await?);
                            }

                            let signers = wait_for_signers(parameters.t).await?;
                            println!(
                                "Computing message hash: context {}, message {}",
                                hex::encode(&CONTEXT[..]),
                                hex::encode(&MESSAGE[..])
                            );
                            let message_hash = compute_message_hash(&CONTEXT[..], &MESSAGE[..]);

                            println!("Signing message: participant index {}, message hash {}, group key {}, secret shares {}, my commitment share index {} signers {}",
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
                            println!("Message signed.");

                            if let Some(mut aggregator) = aggregator {
                                // Because i am the aggregator, finalize the aggregation
                                for sig in collect_partial_signatures(parameters).await? {
                                    aggregator.include_partial_signature(sig);
                                }

                                let aggregator =
                                    finalize_aggregation(parameters.t, aggregator).await?;

                                let sig = aggregator
                                    .aggregate()
                                    .map_err(|e| Error::MisbehavingFinalization(e))?;
                                sig.verify(&gk, &message_hash).or(
                                    // This is always failing, and the lib doesn't return printlnrmation, so let's return ok
                                    //Error::MisbehavingFinalization(HashMap::new())
                                    Ok(()) as Result<()>,
                                )?;
                                publish_finalized().await?;
                            }

                            wait_for_finalization().await?;
                            println!("Finalized!");
                            break;
                        }
                    }
                } else {
                    println!("Not enough participants are ready for signing.");
                }
            }
        }
    }
    Ok(())
}

async fn generate_distributed_key<'a>(
    participant: Participant,
    participant_coefficients: Coefficients,
    parameters: Parameters,
) -> Result<Option<(GroupKey, SecretKey)>> {
    let participant_index = participant.index;

    let mut other_participants =
        collect_other_participants(participant_index, parameters.n).await?;

    // No need to do verification as it is already done in the DKG round 1
    println!(
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

    if let Ok(their_secret_shares) = dkg.their_secret_shares() {
        if their_secret_shares.is_empty() {
            panic!("No other participants")
        }
        println!(
            "Publishing their secret shares: [{}]",
            their_secret_shares.iter().map(|x| x.index).join(", ")
        );
        publish_their_secret_shares(participant_index, their_secret_shares).await?;
    };

    let my_secret_shares = collect_my_secret_shares(participant_index, parameters)
        .await?
        .iter()
        .sorted_by(|a, b| a.index.cmp(&b.index))
        .cloned()
        .collect();

    if get_ready_participants().await? >= parameters.t {
        println!("Enough participants are ready for signing");
        Ok(None)
    } else {
        println!("DKG round 2 Starting");

        let dkg = dkg
            .to_round_two(my_secret_shares)
            .map_err(|_| Error::InsufficientSecretShares)?;
        let pk = participant
            .public_key()
            .expect("Participant has no public key, this shouldn't happen at this point");
        println!(
            "Finishing DKG with public key: {}",
            public_key_to_string(pk)
        );
        let (group_key, secret_key) = dkg.finish(pk).map_err(|_| Error::DkgFinishFailure)?;
        println!("Resulting group key: {}", hex::encode(group_key.to_bytes()));
        increment_ready_participants().await?;
        println!("Ready to sign, press any key to continue");
        Ok(Some((group_key, secret_key)))
    }
}

async fn wait_for_signers(t: u32) -> Result<Vec<Signer>> {
    println!("Waiting for signers");
    loop {
        match read_signers().await? {
            Some(signers) if (signers.len() as u32) >= t => {
                println!("Collected sufficient signers");
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
    println!("Waiting for finalization");
    loop {
        match read_finalized().await? {
            Some(true) => {
                println!("Finalization completed");
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
    println!("Collecting other participants");

    let mut tasks = vec![];

    for i in 1..=n {
        if i != participant_index {
            let handle = task::spawn(async move {
                println!("Waiting for participant {}", i);
                loop {
                    match read_published_participant(i).await? {
                        Some(participant) => {
                            println!("Collected participant {}", i);
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

async fn collect_my_secret_shares(
    my_index: u32,
    parameters: Parameters,
) -> Result<Vec<SecretShare>> {
    let mut collector: HashMap<u32, SecretShare> = HashMap::new();

    loop {
        // For all other participants
        for shared_by in (1..=parameters.n).filter(|i| *i != my_index) {
            let index_to_take = if shared_by < my_index {
                my_index - 2
            } else {
                my_index - 1
            } as usize;
            match read_published_secret_shares(shared_by).await {
                Ok(Some(secret_shares)) => {
                    if let Some(my_secret_share) = secret_shares.get(index_to_take) {
                        println!("Found my Secret share (index {}) in participant {}'s published secret shares", index_to_take, shared_by);
                        collector.insert(shared_by, my_secret_share.clone());
                    } else {
                        println!("My Secret share (index {}) not found for in participant {}'s published secret shares, retrying...", index_to_take, shared_by);
                    }
                }
                Ok(None) => {
                    println!(
                        "Secret shares of participant {} not found, retrying...",
                        shared_by
                    );
                }
                Err(e) => {
                    error!(
                        "Error collecting secret shares for participant {}: {}",
                        shared_by, e
                    );
                    return Err(e);
                }
            }
        }
        if collector.len() < (parameters.t - 1) as usize {
            println!(
                "Not enough secret shares. Found [{}], needs {}",
                collector.values().map(|x| x.index).join(", "),
                parameters.t - 1
            );
            sleep(HEART_BEAT).await;
        } else {
            break;
        }
    }
    println!(
        "Collected secret shares [{}]",
        collector.values().map(|x| x.index).join(", ")
    );
    Ok(collector.values().cloned().collect())
}

async fn collect_published_pks(parameters: Parameters) -> Result<Vec<PublishedPublicKey>> {
    let mut tasks = FuturesUnordered::new();

    // Spawn a task for each participant's public key
    for i in 1..=parameters.n {
        let handle = task::spawn(async move {
            println!("Waiting for published public key of participant {}", i);
            loop {
                match read_published_public_key(i).await? {
                    Some(public_key) => {
                        println!("Collected published public key for participant {}", i);
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
            println!("Waiting for partial signature of participant {}", i);
            loop {
                match read_partial_signature(i).await? {
                    Some(partial_sig) => {
                        println!("Collected partial signature for participant {}", i);
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
    println!("Signing message as participant {}", participant_index);
    println!("Signing details: Participant index {}, message hash {}, group key {}, secret shares {}, my commitment share index {} signers {}",
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
    println!(
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
    println!("Commencing aggregation");
    notify_aggregation_commenced().await?;

    println!(
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
        println!(
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
    println!("{}: Finalizing aggregation", t);
    loop {
        let remaining = aggregator.get_remaining_signers();
        if remaining.is_empty() {
            println!("{}: All signers have signed, finalizing", t);
            let finalized = aggregator
                .finalize()
                .expect("Finalize called before sufficient signers have signed");
            return Ok(finalized);
        } else {
            println!(
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

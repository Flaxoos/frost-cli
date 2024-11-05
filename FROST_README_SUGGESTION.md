# FROST-Dalek

[![Crates.io](https://img.shields.io/crates/v/frost-dalek.svg)](https://crates.io/crates/frost-dalek)
[![Documentation](https://docs.rs/frost-dalek/badge.svg)](https://docs.rs/frost-dalek)
[![Build Status](https://travis-ci.com/github/isislovecruft/frost-dalek.svg?branch=master)](https://travis-ci.org/isislovecruft/frost-dalek)

A Rust implementation of [FROST: Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2020/852) by Chelsea Komlo and Ian Goldberg. This library provides tools for threshold signature schemes, enhancing cryptographic robustness by distributing signing authority among multiple participants.

---

## Overview

FROST-Dalek provides an implementation of threshold Schnorr signatures, where a threshold number of participants must collaborate to create a valid signature on a message. Key features include:

- Flexible configuration of participants and threshold values
- Multi-round key generation via Distributed Key Generation (DKG) and trusted dealer setups
- Round-optimized partial signing and aggregation

However, please note that this library is **experimental** and has known limitations. It may require adjustments before being used in production.

It can only be used for communicating within one program on one machine, and therfore it is not suitable for a distributed setups, and should only be used for further development or testing purposes.

### Key Features

- **Threshold Signature Creation**: Configurable support for `n` participants, where at least `t` participants must sign to generate a valid signature.
- **Flexible Setup**: Allows both DKG (for a decentralized setup) and dealer-based key generation (for trusted setups).
- **No-std Compliance**: Most of the crate is `no_std` compatible, though some parts require `std` due to dependencies on collections such as `HashMap`.

### Known Limitations 
- **No Communication**: The library does not include a communication layer for distributed setups, requiring users to implement serialization and data exchange.
- **Private Struct Members**: Some struct fields are private, particularly in the structs than need to be communicated between participants, namely `Participant`, `SecretShare` and `PartialThresholdSignature`. Because they need to be serialized and sent between participants, this needs to be addressed.
- **API Stability**: This code is experimental and subject to change. Compatibility with future versions may be impacted as FROST protocol designs evolve.

### Major Improvement points:

1. **Add serialization support**: The `Participant`, `SecretShare` and `PartialThresholdSignature` structs need to be de/serializable so they can be broadcasted to all or sent to specific participants. Ideally support for various serialization formats should be added. This can be done by offering features such as `serde` or `bincode`.
2. **Add transport layer**: In addition to the above, a transport layer is needed to enable communication between participants. To fully align with decenteralization principles, this would ideally be done using p2p communication, which can be facilitated by the [rust-libp2p](https://github.com/libp2p/rust-libp2p) crate.
3. **Expose trusted dealer keygen implementation**: At the moment, the `DealtParticipant` can only be used internally, as it's fields are not public and it has no implementation. This prevents any usage and serialization. Since a trusted dealer is explicitly one way to perform key generation, (with the other being distributed key generation), this should be made possible.
4. **Offer a better API to divide secret shares among other participants**: Currently the library user needs to figure out how to distribute each participant's secret shares among other participants, where failure to do so correctly causes verification errors. This logic should be solved by the library and offered as a function of the keygen module. 

```rust
/// A commitment to the dealer's secret polynomial coefficients for Feldman's
/// verifiable secret sharing scheme.
#[derive(Clone, Debug)]
pub struct VerifiableSecretSharingCommitment(pub(crate) Vec<RistrettoPoint>);

/// A participant created by a trusted dealer.
///
/// This can be used to create the participants' keys and secret shares without
/// having to do secret sharing or zero-knowledge proofs.  It's mostly provided
/// for testing and debugging purposes, but there is nothing wrong with using it
/// if you have trust in the dealer to not forge rogue signatures.
#[derive(Clone, Debug)]
pub struct DealtParticipant {
    pub(crate) secret_share: SecretShare,
    pub(crate) public_key: IndividualPublicKey,
    pub(crate) group_key: RistrettoPoint,
}
```
4. **Create meaningful error types**: Currently there is no custom error types defined in the library, and errros are in most cases a Unit type (`Err(())`) or a data structure. An error enum defining the valid error cases should be created with conversions to and from other errors where applicable.
```rust
impl DistributedKeyGeneration<RoundOne> {
    //...
    pub fn new(/*...*/) -> Result<Self, Vec<u32>>
    //...
    pub fn to_round_two(/*...*/) -> Result<DistributedKeyGeneration<RoundTwo>, ()>{}
        //...
        if my_secret_shares.len() != self.state.parameters.n as usize - 1 {
            return Err(());
        }
```
### Minor Improvement points:
- The secret key index should and might as well be public, as it can be obtained by calling `sk.to_public().index` which is an unnecessary overhead
```rust
/// A secret key, used by one participant in a threshold signature scheme, to sign a message.
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    /// The participant index to which this key belongs.
    pub(crate) index: u32,
    /// The participant's long-lived secret share of the group signing key.
    pub(crate) key: Scalar,
}

impl SecretKey {
    /// Derive the corresponding public key for this secret key.
    pub fn to_public(&self) -> IndividualPublicKey {
        let share = &RISTRETTO_BASEPOINT_TABLE * &self.key;

        IndividualPublicKey {
            index: self.index,
            share,
        }
    }
}
```
- The proof verification api seems unnecessarily cumbersome, since it is using members/fns of the `Participant` struct, namely `proof_of_secret_key`, `index` and `public_key()`

```rust    
    participant.proof_of_secret_key.verify(&participant.index, &participant.public_key().unwrap());
```

It can probably be replaced with:

```rust
impl Participant {
    ...
    fn verify_knowledge_of_secret_key(&self, index: u32, public_key: RistrettoPoint) -> Result<(), ()> {
        self.proof_of_secret_key.verify(&index, self.public_key()?)
    }
}
```

## Getting Started

### Installation

Add `frost-dalek` to your `Cargo.toml`:

```toml
[dependencies]
frost-dalek = "0.2.3"
```

### Usage
### Two round approach:
1. **Initial participant creation and publication**:
   Each participant creates a `Participant` instance, which returns a `Coefficients` and `Participant` structs, and publishes only the `Participant`
```rust
   let parameters = Parameters { n: 5, t: 3 };
   let participant_index = 1;
   let (participant, coefficients) = Participant::new(&parameters, participant_index);
   
   // Publish the participant
   publish_participant(&participant);
```
2. **Collect other participants**:
   Each participant collects all other participants:
```rust
    for i in 1..=n {
        if i != participant_index {
            let handle = task::spawn(async move {
                println!("Waiting for participant {}", i);
                loop {
                    match read_published_participant(i)
                    //...
```
3. **Initialize DKG round 1**:
   Each participant initiates the first DKG round, passing the coefficients and other participants to it
```rust
let dkg = DistributedKeyGeneration::new(
    &parameters,
    &participant.index,
    &coefficients,
    &mut other_participants,
).map_err(|e| Error::MisbehavingDkg(e))?; 
```

4. **Secret share broadcast**:
   Each participant broadcasts their secret shares
```rust
if let Ok(their_secret_shares) = dkg.their_secret_shares() {
    publish_their_secret_shares(participant_index, their_secret_shares);
}
```
   And collects the other participants' secret shares
```rust
let my_secret_shares = collect_my_secret_shares(participant_index, parameters);
```
5. **Progress to DKG round 2:** 
   Each participant initiates the second DKG round, passing their secret shares to it
```rust
let dkg_round2 = dkg.to_round_two(my_secret_shares)
    .map_err(|_| Error::InsufficientSecretShares);
```
6. Finish DKG:
   Each participant completes the DKG process, deriving the group public key and individual secret key.
```rust
let pk = participant.public_key().expect("Participant has no public key");
let (group_key, secret_key) = dkg_round2.finish(pk).map_err(|_| Error::DkgFinishFailure);
```
   And publish the public key:
```rust
publish_public_key(participant_index, public_comshares, pk);
```
7. Sign message:
   Each participant signs a message using their individual secret key share, producing a partial signature.
```rust
let message_hash = compute_message_hash(&CONTEXT[..], &MESSAGE[..]);
let partial_signature = secret_key
.sign(&message_hash, &group_key, &mut secret_comshares, 0, signers)
.map_err(|e| Error::Signing(e))?;

// Publish the partial signature
publish_partial_signature(participant_index, partial_signature).await?;
```
8. Aggregate Signatures:
   The designated aggregator, which could be anyone, potentially first come first served, collects the partial signatures and assembles them into a complete threshold signature.
```rust
let mut aggregator = SignatureAggregator::new(parameters, group_key, &CONTEXT[..], &MESSAGE[..]);

for partial_sig in collect_partial_signatures(parameters).await? {
    aggregator.include_partial_signature(partial_sig);
}

let threshold_signature = aggregator.aggregate()?;
```

9. Verify signature:
Each participant verifies the threshold signature using the group public key to ensure authenticity.
```rust
let is_verified = threshold_signature.verify(&group_key, &message_hash)?;
println!("Signature verification result: {}", is_verified);
```
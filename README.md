### Your task is to demonstrate the use of this library by making a small CLI utility that uses the library to:
- #### Generate a public key and at least 5 shares of the private key 
- #### Dump these to disc
- #### Use these to sign an arbitrary message.
#### (Observe that threshold signing on a single machine defeats the purpose of threshold signing, but we are just interested in a demonstration of the library for this challenge.)


### FROST: Flexible Round-Optimized
#### Schnorr Threshold Signatures
> Threshold signature schemes are a cryptographic primitive to facilitate joint ownership
> over a private key by a set of participants, such that a threshold number of participants
> must cooperate to issue a signature that can be verified by a single public key

## Process according to [Chelsea Komlo](https://youtu.be/g3RX4IXAtrE?si=WGJnh-z_5ZlOsOQs&t=664):

| Step    | Participant                                                                                                                                                                                                                        | Commitment Server                  | Signature Aggregator                                               |
|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|--------------------------------------------------------------------| 
| Keygen | - Generate two nonces<br/> - Generate two commitments to these nonces<br/> - Store private commitments locally<br/> - Publish the public commitments to some place ==><br/>(all of the other parties or cached for later use) | <br/><br/><br/>- Store commitments |
| Sign | <br/> <br/> <br/> Generate binding value, which is a hash with respect to the index for this participant, the message to be assigned and this b value which constitutes all of the commitments                                     | | - `B = map i in 1..t { (i, commitments[i]) }`<br/><== (message, B) |


The main issue is that there isn't a distinguishing between a commitment and a partial signature
- because a secret key is needed for signing, and because a secret key can only be obtained by completing the two stages of distributed key generation, it is impossible to complete the single stage round signature
- The precomputation and partial signature approach is a single round approach
### Lib doc issues:
1) This is misleading, it seems to be a continuation of the previous part, but this is infact the single round approach 
    > **Precomputation and Partial Signatures**<br/><br/>
    Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon message with their respective secret keys, which they can then give to an untrusted SignatureAggregator (which can be one of the participants) to create a 2-out-of-3 threshold signature. To do this, they each pre-compute (using generate_commitment_share_lists) and publish a list of commitment shares.
2) The doc says that verification should be done by the participants, but it is also done in the DKG first round
3) IndividualPublicKey::verify is unimplemented and it doesn't say it in it's doc
4) Wrong documentation for `ThresholdSignature::verify`, returns `Result<(), ()>` instead of `Result<Vec<u32>, ()>`
```rust
impl ThresholdSignature {
/// Verify this [`ThresholdSignature`].
///
/// # Returns
///
/// A `Result` whose `Ok` value is an empty tuple if the threshold signature
/// was successfully verified, otherwise a vector of the participant indices
/// of any misbehaving participants.
pub fn verify(&self, group_key: &GroupKey, message_hash: &[u8; 64]) -> Result<(), ()> {

```
 
### Lib API issues:
- Proof of secret key cannot be published, as it's fields are private, this means that verification by the other participants is impossible, and neither is round one initialization, as it requires verification as well 
- Parameters n should be usize(?)
- IndividualPublicKey::verify is unimplemented
- Dkg.their_secret_shares() returns converts an option to a result which seems unnecessary (option is none if no other participants, so that's a valid state, can just leave it as option) 
```rust

/// Retrieve a secret share for each other participant, to be given to them
/// at the end of `DistributedKeyGeneration::<RoundOne>`.
pub fn their_secret_shares(&self) -> Result<&Vec<SecretShare>, ()> {
    self.state.their_secret_shares.as_ref().ok_or(())
}
// ...
for p in other_participants.iter() {
    their_secret_shares.push(SecretShare::evaluate_polynomial(&p.index, my_coefficients));
}
```
- Implement errors, instead of returning Result<T, ()> everywhere
```rust
#[derive(Zeroize)]
#[zeroize(drop)] // <-- uses deprecated zeorize attr, 
// should use ZeroizeOnDrop which comes from a newer version of Zeorize crate currently using v1 
pub struct Coefficients(pub(crate) Vec<Scalar>);
```
The dealer based keygen is unusable because both `DealtParticipant` and `VerifiableSecretSharingCommitment` have no impls and all of their fields are private.
The lib says it should only be used for testing and debugging but a trusted dealer is explicitly one way to perform keygen, with the other being DKG
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

The secret key index might as well be public, as it can be obtained by calling `sk.to_public().index` which is an unnecessary overhead
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

the proof verification api seems unnecessarily cumbersome 
```rust
participant.proof_of_secret_key.verify(&participant.index, &participant.public_key().unwrap());
```

since it's using members/fns of the `Participant` struct, namely `proof_of_secret_key`, `index` and `public_key()`, it can be replaced with:
```rust
impl Participant {
    ...
    fn verify_knowledge_of_secret_key(&self, index: u32, public_key: RistrettoPoint) -> Result<(), ()> {
        self.proof_of_secret_key.verify(&index, self.public_key()?)
    }
}
```
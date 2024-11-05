# CLI Tool for demonstrating the use of the rust FROST library - Ido Flax

----

## Instructions
- run `sh setup.sh {n} {t}`, where {n} is the number of shares and {t} is the threshold and `n >= 5` and `n >= t`, for example:
    ```shell
    sh setup.sh 5 3
    ```
- Run ```cargo run -- start-session --participant-index {participant_index}``` for each participant where `participant_index` is the 1-indexed participant index, for example:

   ```cargo run --package zama -- start-session --participant-index 1```
   
   ```cargo run --package zama -- start-session --participant-index 2```
   
   ```cargo run --package zama -- start-session --participant-index 3```
   
   ```cargo run --package zama -- start-session --participant-index 4```
   
   ```cargo run --package zama -- start-session --participant-index 5```

- Each participant would see messages reporting the key generation process and will be prompted to press any key to continue once their keygen is ready

## Caveats
- Currently any excess signers (n-t) will get errors, where as the others will get success message (WIP to prevent the excess signers from continuing)
- Not handling all edge cases of user input atm, some input validation exists

---

## Issues With Library
- The main issue is that there is no way to communicate between the signers, as the secret shares and public key are not serializable.
As a workaround for that, this tool uses unsafe memory access to write the struct bytes to files, but this is not ideal and is prone to failures if the structs in the library change.

- Additionally, there is no distinction between single and multi-round threshold signatures, it seems the two concepts are mixed, at least according to the crate docs.
Specially, because a secret key is needed for signing, and because a secret key can only be obtained by completing the two stages of distributed key generation, it is impossible to complete the single stage round signature
- 
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

5) toRoundTwo should hanbdle sorting:
```rust
        for share in my_secret_shares.iter() {
            // XXX TODO implement sorting for SecretShare and also for a new Commitment type
            for (index, commitment) in self.state.their_commitments.iter() {
                if index == &share.index {
                    share.verify(commitment)?;
                }
            }
        }
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
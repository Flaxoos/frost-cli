use frost_dalek::signature::PartialThresholdSignature;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct PartialThresholdSignatureWrapper(
    #[serde(with = "partial_threshold_signature_serde")] pub PartialThresholdSignature,
);

pub mod partial_threshold_signature_serde {
    use super::*;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use serde::{Deserializer, Serializer};
    use std::mem::size_of;
    use std::ptr;

    /// Custom serialization for `PartialThresholdSignature` using raw memory access
    pub fn serialize<S>(sig: &PartialThresholdSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the entire struct as raw bytes
        let bytes = unsafe {
            std::slice::from_raw_parts(
                sig as *const _ as *const u8,
                size_of::<PartialThresholdSignature>(),
            )
        };
        let encoded = BASE64_STANDARD.encode(bytes); // Encode bytes as a Base64 string
        serializer.serialize_str(&encoded)
    }

    /// Custom deserialization for `PartialThresholdSignature` using Base64 decoding
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PartialThresholdSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = PartialThresholdSignature;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a Base64 encoded byte array of size matching PartialThresholdSignature")
            }

            fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes = BASE64_STANDARD.decode(encoded).map_err(|_| {
                    serde::de::Error::custom("Failed to decode Base64 string for PartialThresholdSignature")
                })?;

                if bytes.len() != size_of::<PartialThresholdSignature>() {
                    return Err(serde::de::Error::custom("Invalid byte length for PartialThresholdSignature"));
                }

                Ok(unsafe { ptr::read(bytes.as_ptr() as *const PartialThresholdSignature) })
            }
        }

        deserializer.deserialize_str(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::partial_sig_serde::PartialThresholdSignatureWrapper;
    use frost_dalek::keygen::RoundOne;
    use frost_dalek::signature::PartialThresholdSignature;
    use frost_dalek::{compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, Parameters, Participant, SignatureAggregator};
    use rand::rngs::OsRng;
    use serde_json;

    #[test]
    fn test_serialize_deserialize_partial_threshold_signature() {
        frost_with_serde_partial_sigs(|partial_sig| {
            let wrapper = PartialThresholdSignatureWrapper(partial_sig);

            let serialized = serde_json::to_string(&wrapper).expect("Serialization failed");
            println!("{}", serialized);

            let deserialized: PartialThresholdSignatureWrapper =
                serde_json::from_str(&serialized).unwrap();
            deserialized.0
        });
    }

    fn frost_with_serde_partial_sigs(serde: impl Fn(PartialThresholdSignature) -> PartialThresholdSignature) {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut p2_other_participants).unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let p3_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p3.index,
                                                          &p3coeffs,
                                                          &mut p3_other_participants).unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p4.index,
                                                          &p4coeffs,
                                                          &mut p4_other_participants).unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &p5.index,
                                                          &p5coeffs,
                                                          &mut p5_other_participants).unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec!(p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_secret_shares[0].clone(),
                                       p4_their_secret_shares[0].clone(),
                                       p5_their_secret_shares[0].clone());

        let p2_my_secret_shares = vec!(p1_their_secret_shares[0].clone(),
                                       p3_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[1].clone(),
                                       p5_their_secret_shares[1].clone());

        let p3_my_secret_shares = vec!(p1_their_secret_shares[1].clone(),
                                       p2_their_secret_shares[1].clone(),
                                       p4_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[2].clone());

        let p4_my_secret_shares = vec!(p1_their_secret_shares[2].clone(),
                                       p2_their_secret_shares[2].clone(),
                                       p3_their_secret_shares[2].clone(),
                                       p5_their_secret_shares[3].clone());

        let p5_my_secret_shares = vec!(p1_their_secret_shares[3].clone(),
                                       p2_their_secret_shares[3].clone(),
                                       p3_their_secret_shares[3].clone(),
                                       p4_their_secret_shares[3].clone());

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(p1.public_key().unwrap()).unwrap();
        let (_, _) = p2_state.finish(p2.public_key().unwrap()).unwrap();
        let (_, p3_sk) = p3_state.finish(p3.public_key().unwrap()).unwrap();
        let (_, p4_sk) = p4_state.finish(p4.public_key().unwrap()).unwrap();
        let (_, _) = p5_state.finish(p5.public_key().unwrap()).unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a tests of the tsunami alert system. This is only a tests.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, mut p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, mut p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
        let p3_partial = p3_sk.sign(&message_hash, &group_key, &mut p3_secret_comshares, 0, signers).unwrap();
        let p4_partial = p4_sk.sign(&message_hash, &group_key, &mut p4_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(serde(p1_partial));
        aggregator.include_partial_signature(serde(p3_partial));
        aggregator.include_partial_signature(serde(p4_partial));

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }
}
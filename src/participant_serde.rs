use frost_dalek::Participant;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ParticipantWrapper(#[serde(with = "participant_serde")] pub Participant);
pub mod participant_serde {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use frost_dalek::nizk::NizkOfSecretKey;
    use frost_dalek::Participant;
    use serde::de::{Error as SerdeError, Visitor};
    use serde::ser::{SerializeStruct, Serializer};
    use serde::Deserializer;
    use std::fmt;
    use std::mem::size_of;
    use std::ptr;

    pub fn serialize<S>(participant: &Participant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Participant", 3)?;

        state.serialize_field("index", &participant.index)?;

        let compressed_commitments: Vec<[u8; 32]> = participant
            .commitments
            .iter()
            .map(|point| point.compress().to_bytes())
            .collect();
        state.serialize_field("commitments", &compressed_commitments)?;

        let proof_of_secret_key_bytes = unsafe {
            // SAFETY: The following conditions make it safe to interpret `NizkOfSecretKey` as raw bytes:
            // 1. `NizkOfSecretKey` contains only two `Scalar` fields, with no internal pointers or references.
            // 2. Each `Scalar` has a `bytes` field (`[u8; 32]`) that is suitable for raw byte interpretation.
            // 3. `size_of::<NizkOfSecretKey>()` correctly reflects the size in memory as `64` bytes,
            //    given the predictable layout of the `Scalar` struct.
            std::slice::from_raw_parts(
                &participant.proof_of_secret_key as *const _ as *const u8,
                size_of::<NizkOfSecretKey>(),
            )
        };
        state.serialize_field("proof_of_secret_key", &proof_of_secret_key_bytes)?;

        state.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Participant, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ParticipantVisitor;

        impl<'de> Visitor<'de> for ParticipantVisitor {
            type Value = Participant;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid byte array representing a Participant")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Participant, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Deserialize `index`
                let index: u32 = seq
                    .next_element()?
                    .ok_or_else(|| SerdeError::custom("Missing index"))?;

                // Deserialize `commitments`
                let compressed_commitments: Vec<[u8; 32]> = seq
                    .next_element()?
                    .ok_or_else(|| SerdeError::custom("Missing commitments"))?;
                let commitments = compressed_commitments
                    .iter()
                    .map(|bytes| {
                        CompressedRistretto::from_slice(bytes)
                            .decompress()
                            .ok_or_else(|| SerdeError::custom("Invalid RistrettoPoint"))
                    })
                    .collect::<Result<Vec<RistrettoPoint>, A::Error>>()?;

                // Deserialize `proof_of_secret_key`
                let proof_of_secret_key_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| SerdeError::custom("Missing proof_of_secret_key"))?;
                let proof_of_secret_key: NizkOfSecretKey =
                    unsafe { ptr::read(proof_of_secret_key_bytes.as_ptr() as *const _) };

                Ok(Participant {
                    index,
                    commitments,
                    proof_of_secret_key,
                })
            }
        }

        deserializer.deserialize_struct(
            "Participant",
            &["index", "commitments", "proof_of_secret_key"],
            ParticipantVisitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use frost_dalek::{Parameters, Participant};
    use rand::rngs::OsRng;

    #[test]
    fn test_serialize_deserialize_participant() {
        let index = 1u32;
        let parameters = Parameters { n: 1, t: 1 };
        let (participant, coefficients) = Participant::new(&parameters, index);
        
        let wrapper = ParticipantWrapper(participant.clone());
        
        let serialized = bincode::serialize(&wrapper).unwrap();
        let deserialized: ParticipantWrapper = bincode::deserialize(&serialized).unwrap();

        let deserialized_participant = deserialized.0;

        assert_eq!(
            participant.index, deserialized_participant.index,
            "Index mismatch: {} != {}",
            participant.index, deserialized_participant.index
        );
        assert_eq!(
            participant.commitments, deserialized_participant.commitments,
            "Commitments mismatch: {:?} != {:?}",
            participant.commitments, deserialized_participant.commitments
        );

        let pk = participant.public_key().unwrap();
        assert_eq!(
            participant.proof_of_secret_key.verify(&index, pk).unwrap(),
            deserialized_participant
                .proof_of_secret_key
                .verify(&index, pk)
                .unwrap(),
            "Proof of secret key mismatch"
        );

        let mut rng = OsRng;
        let dummy_pk = RistrettoPoint::random(&mut rng);

        assert_eq!(
            participant.proof_of_secret_key.verify(&index, &dummy_pk).is_err(),
            deserialized_participant
                .proof_of_secret_key
                .verify(&index, &dummy_pk).is_err(),
            "Proof of secret key mismatch"
        );
    }
}

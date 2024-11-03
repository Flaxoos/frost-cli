use frost_dalek::keygen::SecretShare;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SecretShareWrapper(#[serde(with = "secret_share_serde")] pub Vec<SecretShare>);

pub mod secret_share_serde {
    use frost_dalek::keygen::SecretShare;
    use serde::de::{Deserializer, Error as SerdeError, Visitor};
    use serde::ser::{SerializeStruct, Serializer};
    use std::fmt;
    use std::mem::size_of;
    use std::ptr;

    /// Custom serialization for `Vec<SecretShare>` using `serde`
    pub fn serialize<S>(shares: &Vec<SecretShare>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize each `SecretShare` in the vector
        let mut state = serializer.serialize_struct("SecretShares", shares.len())?;
        for share in shares {
            state.serialize_field("SecretShare", &share.index)?;

            // Serialize `polynomial_evaluation` as raw bytes
            let secret_share_bytes = unsafe {
                std::slice::from_raw_parts(share as *const _ as *const u8, size_of::<SecretShare>())
            };
            state.serialize_field("raw_bytes", &secret_share_bytes)?;
        }

        state.end()
    }

    /// Custom deserialization for `Vec<SecretShare>` using `serde`
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<SecretShare>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretSharesVisitor;

        impl<'de> Visitor<'de> for SecretSharesVisitor {
            type Value = Vec<SecretShare>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of SecretShare structs")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<SecretShare>, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut shares = Vec::new();

                while let Some(index) = seq.next_element::<u32>()? {
                    // Deserialize the raw bytes for `SecretShare`
                    let raw_bytes: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| SerdeError::custom("Missing raw bytes for SecretShare"))?;

                    if raw_bytes.len() != size_of::<SecretShare>() {
                        return Err(SerdeError::custom("Invalid raw bytes length for SecretShare"));
                    }

                    // SAFETY: `SecretShare` has a predictable layout and `raw_bytes` is the exact
                    // size of `SecretShare`.
                    let secret_share = unsafe { ptr::read(raw_bytes.as_ptr() as *const SecretShare) };

                    shares.push(secret_share);
                }

                Ok(shares)
            }
        }

        deserializer.deserialize_struct("SecretShares", &["index", "raw_bytes"], SecretSharesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretShareWrapper;
    use bincode;
    use frost_dalek::{DistributedKeyGeneration, Parameters, Participant};

    #[test]
    fn test_serialize_deserialize_secret_shares() {
        let params = Parameters { t: 1, n: 2 };
        let participant = Participant::new(&params, 0);
        let other_participant = Participant::new(&params, 1);
        let dkg_1 = DistributedKeyGeneration::new(
            &params,
            &0,
            &participant.1,
            &mut vec![other_participant.0],
        );

        // Collect a vector of secret shares
        let secret_shares = dkg_1.unwrap().their_secret_shares().unwrap().clone();

        // Wrap the vector in SecretShareWrapper
        let wrapper = SecretShareWrapper(secret_shares.clone());

        // Serialize the wrapped vector of SecretShares
        let serialized = bincode::serialize(&wrapper).unwrap();

        // Deserialize it back to a SecretShareWrapper
        let deserialized: SecretShareWrapper = bincode::deserialize(&serialized).unwrap();

        // Extract the inner Vec<SecretShare>
        let deserialized_shares = deserialized.0;
        
        assert!(deserialized_shares.len() > 0);
        assert_eq!(secret_shares.len(), deserialized_shares.len());

        // Assert that each deserialized SecretShare matches the original
        for (original, deserialized) in secret_shares.iter().zip(deserialized_shares.iter()) {
            assert_eq!(original.index, deserialized.index, "Index mismatch");
            // TODO: Test `polynomial_evaluation`, which is private
        }
    }
}
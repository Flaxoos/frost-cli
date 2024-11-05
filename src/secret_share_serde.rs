use frost_dalek::keygen::SecretShare;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wrapper for serializing and deserializing `SecretShare` as raw bytes.
pub struct SecretShareWrapper(pub SecretShare);

pub mod secret_share_serde {
    use crate::secret_share_serde::SecretShareWrapper;
    use frost_dalek::keygen::SecretShare;
    use serde::de::{Deserializer, Error as SerdeError, SeqAccess, Visitor};
    use serde::ser::{SerializeStruct, Serializer};
    use serde::{Deserialize, Serialize};
    use std::ptr;
    use std::{fmt, mem};

    impl Serialize for SecretShareWrapper {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Convert the entire `SecretShare` to raw bytes
            let secret_share_bytes = unsafe {
                std::slice::from_raw_parts(
                    &self.0 as *const SecretShare as *const u8,
                    mem::size_of::<SecretShare>(),
                )
            };

            // Serialize as a byte array
            serializer.serialize_bytes(secret_share_bytes)
        }
    }

    impl<'de> Deserialize<'de> for SecretShareWrapper {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct SecretShareVisitor;

            impl<'de> Visitor<'de> for SecretShareVisitor {
                type Value = SecretShareWrapper;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a byte array representing SecretShare")
                }

                fn visit_bytes<E>(self, value: &[u8]) -> Result<SecretShareWrapper, E>
                where
                    E: serde::de::Error,
                {
                    if value.len() != mem::size_of::<SecretShare>() {
                        return Err(serde::de::Error::invalid_length(value.len(), &self));
                    }

                    // Recreate `SecretShare` from raw bytes
                    let secret_share = unsafe { ptr::read(value.as_ptr() as *const SecretShare) };
                    Ok(SecretShareWrapper(secret_share))
                }
            }

            deserializer.deserialize_bytes(SecretShareVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::secret_share_serde::SecretShareWrapper;
    use bincode;
    use frost_dalek::{DistributedKeyGeneration, Parameters, Participant};
    use itertools::Itertools;

    #[test]
    fn test_serialize_deserialize_secret_shares() {
        let params = Parameters { t: 1, n: 3 };
        let p1 = Participant::new(&params, 1);
        let p2 = Participant::new(&params, 2);
        let p3 = Participant::new(&params, 3);
        let dkg_1 = DistributedKeyGeneration::new(&params, &1, &p1.1, &mut vec![p2.0, p3.0]);

        // Collect a vector of secret shares
        let secret_shares = dkg_1.unwrap().their_secret_shares().unwrap().clone();

        // Serialize the wrapped vector of SecretShares
        let serialized_vec: Vec<Vec<u8>> = secret_shares.clone()
            .into_iter()
            .map(|s| SecretShareWrapper(s))
            .map(|w| bincode::serialize(&w).unwrap())
            .collect_vec();

        // Deserialize it back to a SecretShareWrapper
        let deserialized_vec: Vec<SecretShareWrapper> = serialized_vec
            .into_iter()
            .map(|s| bincode::deserialize(&s).unwrap())
            .collect_vec();
        

        assert!(deserialized_vec.len() > 0);
        assert_eq!(secret_shares.clone().len(), deserialized_vec.len());

        // Assert that each deserialized SecretShare matches the original
        for (original, deserialized) in secret_shares.into_iter().zip(deserialized_vec.into_iter().map(|x|x.0)) {
            assert_eq!(original.index, deserialized.index, "Index mismatch");
        }
    }
}

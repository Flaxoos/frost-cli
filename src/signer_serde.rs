use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use frost_dalek::signature::Signer;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct SignerWrapper(
    #[serde(with = "signer_serde")]
    pub Signer
);

/// Serialization module for `Signer`
pub mod signer_serde {
    use super::*;
    use frost_dalek::signature::Signer;
    use serde::de::{self, Deserializer, Visitor};
    use serde::ser::SerializeStruct;
    use serde::Serializer;

    pub fn serialize<S>(signer: &Signer, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Signer", 2)?;
        state.serialize_field("participant_index", &signer.participant_index)?;

        // Compress the RistrettoPoints for serialization
        let compressed_commitment_share = (
            signer.published_commitment_share.0.compress().to_bytes(),
            signer.published_commitment_share.1.compress().to_bytes(),
        );
        state.serialize_field("published_commitment_share", &compressed_commitment_share)?;

        state.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signer, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            participant_index: u32,
            published_commitment_share: ([u8; 32], [u8; 32]),
        }

        let helper = Helper::deserialize(deserializer)?;
        let point1 = CompressedRistretto(helper.published_commitment_share.0)
            .decompress()
            .ok_or_else(|| de::Error::custom("Failed to decompress RistrettoPoint"))?;
        let point2 = CompressedRistretto(helper.published_commitment_share.1)
            .decompress()
            .ok_or_else(|| de::Error::custom("Failed to decompress RistrettoPoint"))?;

        Ok(Signer {
            participant_index: helper.participant_index,
            published_commitment_share: (point1, point2),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use frost_dalek::signature::Signer;
    use rand::rngs::OsRng;
    use serde_json;

    #[test]
    fn test_serialize_deserialize_signer() {
        // Generate random RistrettoPoints for the commitment share
        let point1 = RistrettoPoint::random(&mut OsRng);
        let point2 = RistrettoPoint::random(&mut OsRng);

        // Create a Signer with dummy data
        let original_signer = Signer {
            participant_index: 42,
            published_commitment_share: (point1, point2),
        };

        // Wrap it in SignerWrapper for serialization
        let wrapper = SignerWrapper(original_signer);

        // Serialize the wrapper
        let serialized = serde_json::to_string(&wrapper).expect("Serialization failed");

        // Deserialize it back
        let deserialized: SignerWrapper =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        // Check that the original and deserialized values match
        assert_eq!(original_signer.participant_index, deserialized.0.participant_index);
        assert_eq!(
            original_signer.published_commitment_share.0.compress(),
            deserialized.0.published_commitment_share.0.compress()
        );
        assert_eq!(
            original_signer.published_commitment_share.1.compress(),
            deserialized.0.published_commitment_share.1.compress()
        );
    }
}
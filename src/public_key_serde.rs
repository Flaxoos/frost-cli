use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use frost_dalek::IndividualPublicKey;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IndividualPublicKeyWrapper(
    #[serde(with = "individual_public_key_serde")]
    pub IndividualPublicKey
);

/// Serialization module for `IndividualPublicKey`
pub mod individual_public_key_serde {
    use frost_dalek::IndividualPublicKey;
    use super::*;
    use serde::de::{self, Deserializer, Visitor};
    use serde::ser::SerializeStruct;
    use serde::Serializer;

    pub fn serialize<S>(key: &IndividualPublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("IndividualPublicKey", 2)?;
        state.serialize_field("index", &key.index)?;

        let compressed_share = key.share.compress().to_bytes();
        state.serialize_field("share", &compressed_share)?;

        state.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IndividualPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            index: u32,
            share: [u8; 32],
        }

        let helper = Helper::deserialize(deserializer)?;
        let share = CompressedRistretto(helper.share)
            .decompress()
            .ok_or_else(|| de::Error::custom("Failed to decompress RistrettoPoint"))?;

        Ok(IndividualPublicKey {
            index: helper.index,
            share,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use frost_dalek::IndividualPublicKey;
    use rand::rngs::OsRng;
    use serde_json;

    #[test]
    fn test_serialize_deserialize_individual_public_key() {
        let share = RistrettoPoint::random(&mut OsRng);

        let original_key = IndividualPublicKey {
            index: 42,
            share,
        };

        let wrapper = IndividualPublicKeyWrapper(original_key.clone());

        let serialized = serde_json::to_string(&wrapper).expect("Serialization failed");

        let deserialized: IndividualPublicKeyWrapper =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(original_key.index, deserialized.0.index);
        assert_eq!(original_key.share.compress(), deserialized.0.share.compress());
    }
}
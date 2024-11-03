use frost_dalek::IndividualPublicKey;
use frost_dalek::precomputation::PublicCommitmentShareList;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct PublicCommitmentShareListWrapper(
    #[serde(with = "comshare_serde")] pub PublicCommitmentShareList,
);

pub mod comshare_serde {
    use super::*;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::de::{self, Deserializer, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::Serializer;

    pub fn serialize<S>(list: &PublicCommitmentShareList, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PublicCommitmentShareList", 2)?;

        state.serialize_field("participant_index", &list.participant_index)?;

        let compressed_commitments: Vec<([u8; 32], [u8; 32])> = list
            .commitments
            .iter()
            .map(|(point1, point2)| (point1.compress().to_bytes(), point2.compress().to_bytes()))
            .collect();
        state.serialize_field("commitments", &compressed_commitments)?;

        state.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicCommitmentShareList, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            participant_index: u32,
            commitments: Vec<([u8; 32], [u8; 32])>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let commitments = helper
            .commitments
            .into_iter()
            .map(|(bytes1, bytes2)| {
                let point1 = CompressedRistretto(bytes1)
                    .decompress()
                    .ok_or_else(|| de::Error::custom("Failed to decompress RistrettoPoint"))?;
                let point2 = CompressedRistretto(bytes2)
                    .decompress()
                    .ok_or_else(|| de::Error::custom("Failed to decompress RistrettoPoint"))?;
                Ok((point1, point2))
            })
            .collect::<Result<Vec<_>, D::Error>>()?;

        Ok(PublicCommitmentShareList {
            participant_index: helper.participant_index,
            commitments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use serde_json;

    #[test]
    fn test_serialize_deserialize_public_commitment_share_list() {
        let point1 = RistrettoPoint::random(&mut rand::thread_rng());
        let point2 = RistrettoPoint::random(&mut rand::thread_rng());
        let point3 = RistrettoPoint::random(&mut rand::thread_rng());
        let point4 = RistrettoPoint::random(&mut rand::thread_rng());

        let original_list = PublicCommitmentShareList {
            participant_index: 42,
            commitments: vec![(point1, point2), (point3, point4)],
        };

        let commitments = original_list.commitments.clone();
        let participant_index = original_list.participant_index;
        let wrapper = PublicCommitmentShareListWrapper(original_list);

        let serialized = serde_json::to_string(&wrapper).expect("Serialization failed");

        let deserialized: PublicCommitmentShareListWrapper =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(participant_index, deserialized.0.participant_index);
        assert_eq!(commitments.len(), deserialized.0.commitments.len());

        for ((orig1, orig2), (des1, des2)) in commitments
            .into_iter()
            .zip(deserialized.0.commitments.iter())
        {
            assert_eq!(orig1.compress(), des1.compress(), "Point 1 does not match");
            assert_eq!(orig2.compress(), des2.compress(), "Point 2 does not match");
        }
    }
}

use crate::serde_mods::{
    ristretto_point_serde, vec_ristretto_point_pair_serde, vec_ristretto_point_serde,
};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use frost_dalek::precomputation::{CommitmentShare, SecretCommitmentShareList};
use frost_dalek::{GroupKey, IndividualPublicKey};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;


#[derive(Serialize, Deserialize)]
struct KeygenOutput {
    group_key: Vec<u8>,
    shares: HashMap<u32, ShareOutput>,
}
#[derive(Serialize, Deserialize)]
pub struct ShareOutput {
    #[serde(with = "vec_ristretto_point_pair_serde")]
    pub public_commitments: Vec<(CompressedRistretto, CompressedRistretto)>,
}

#[derive(Serialize, Deserialize)]
pub struct PublishedCommitments(
    #[serde(with = "vec_ristretto_point_serde")]
    pub Vec<RistrettoPoint>
);

#[derive(Serialize, Deserialize)]
pub struct SerializableGroupKey(pub(crate) [u8; 32]);

impl From<GroupKey> for SerializableGroupKey {
    fn from(group_key: GroupKey) -> Self {
        SerializableGroupKey(group_key.to_bytes())
    }
}

impl TryFrom<SerializableGroupKey> for GroupKey {
    type Error = ();

    fn try_from(value: SerializableGroupKey) -> Result<Self, Self::Error> {
        GroupKey::from_bytes(value.0)
    }
}

// Wrapper for IndividualPublicKey
#[derive(Serialize, Deserialize)]
pub struct SerializableIndividualPublicKey {
    pub index: u32,
    #[serde(with = "ristretto_point_serde")]
    pub share: RistrettoPoint,
}

impl From<IndividualPublicKey> for SerializableIndividualPublicKey {
    fn from(pub_key: IndividualPublicKey) -> Self {
        SerializableIndividualPublicKey {
            index: pub_key.index,
            share: pub_key.share,
        }
    }
}

impl From<SerializableIndividualPublicKey> for IndividualPublicKey {
    fn from(wrapper: SerializableIndividualPublicKey) -> Self {
        IndividualPublicKey {
            index: wrapper.index,
            share: wrapper.share,
        }
    }
}

#[derive(Debug)]
pub struct SerializableSecretCommitmentShareList {
    /// The secret commitment shares.
    pub commitments: Vec<CommitmentShare>,
}

impl From<SecretCommitmentShareList> for SerializableSecretCommitmentShareList {
    fn from(secret_commitment_share_list: SecretCommitmentShareList) -> Self {
        SerializableSecretCommitmentShareList {
            commitments: secret_commitment_share_list.commitments,
        }
    }
}

impl Serialize for SerializableSecretCommitmentShareList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("{:?}", self.commitments).serialize(serializer)
    }
}

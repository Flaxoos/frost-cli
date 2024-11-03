use serde::{Deserialize, Serialize, Serializer};

// Wrapper for GroupKey
// #[derive(Serialize, Deserialize)]
// pub struct SerializableGroupKey(#[serde(with = "ristretto_point_serde")] pub(crate)RistrettoPoint);

pub mod vec_ristretto_point_serde {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use serde::de::Error;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(points: &Vec<RistrettoPoint>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes_vec: Vec<[u8; 32]> = points.iter().map(|p| p.compress().to_bytes()).collect();
        serializer.serialize_seq(Some(bytes_vec.len()))?.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RistrettoPoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec: Vec<[u8; 32]> = Vec::<[u8; 32]>::deserialize(deserializer)?;
        let mut vec = vec![];
        for bytes in bytes_vec.iter() {
            let point = bytes_to_compressed_ristretto(bytes)
                .decompress()
                .ok_or(Error::custom(
                    "CompressedRistretto was not the canonical encoding of a point",
                ))?;
            vec.push(point)
        }
        Ok(vec)
    }

    fn bytes_to_compressed_ristretto(bytes: &[u8; 32]) -> CompressedRistretto {
        let mut tmp = [0u8; 32];

        tmp.copy_from_slice(bytes);

        CompressedRistretto(tmp)
    }
}

pub mod vec_compressed_ristretto_point_serde {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::de::Error;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(points: &Vec<CompressedRistretto>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes_vec: Vec<&[u8; 32]> = points.iter().map(|p| p.as_bytes()).collect();
        serializer.serialize_seq(Some(bytes_vec.len()))?.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<CompressedRistretto>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec: Vec<&[u8]> = Vec::<&[u8]>::deserialize(deserializer)?;
        let mut vec = vec![];
        for bytes in bytes_vec.iter() {
            match bytes_to_compressed_ristretto(bytes) {
                Ok(compressed_ristretto) => vec.push(compressed_ristretto),
                Err(msg) => return Err(Error::custom(msg)),
            }
        }
        Ok(vec)
    }

    fn bytes_to_compressed_ristretto(bytes: &[u8]) -> Result<CompressedRistretto, &str> {
        if bytes.len() != 32 {
            Err("CompressedRistretto bytes length must be 32")
        } else {
            let mut tmp = [0u8; 32];

            tmp.copy_from_slice(bytes);

            Ok(CompressedRistretto(tmp))
        }
    }
}

pub mod vec_ristretto_point_pair_serde {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::de::Error;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        points: &Vec<(CompressedRistretto, CompressedRistretto)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes_vec: Vec<(&[u8; 32], &[u8; 32])> = points
            .iter()
            .map(|(p1, p2)| (p1.as_bytes(), p2.as_bytes()))
            .collect();
        serializer.serialize_seq(Some(bytes_vec.len()))?.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<(CompressedRistretto, CompressedRistretto)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec = Vec::<(&[u8], &[u8])>::deserialize(deserializer)?;
        let mut vec = vec![];
        for (bytes1, bytes2) in bytes_vec.iter() {
            match (
                bytes_to_compressed_ristretto(bytes1),
                bytes_to_compressed_ristretto(bytes2),
            ) {
                (Ok(compressed_ristretto1), Ok(compressed_ristretto2)) => {
                    vec.push((compressed_ristretto1, compressed_ristretto2))
                }
                _ => return Err(Error::custom("CompressedRistretto bytes length must be 32")),
            }
        }
        Ok(vec)
    }

    fn bytes_to_compressed_ristretto(bytes: &[u8]) -> Result<CompressedRistretto, ()> {
        if bytes.len() != 32 {
            Err(())
        } else {
            let mut tmp = [0u8; 32];

            tmp.copy_from_slice(bytes);

            Ok(CompressedRistretto(tmp))
        }
    }
}

pub mod ristretto_point_serde {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let compressed = point.compress(); // Compress to get byte array
        serializer.serialize_bytes(compressed.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        let compressed = CompressedRistretto::from_slice(bytes);
        compressed
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("Failed to decompress RistrettoPoint"))
    }
}

pub mod scalar_serde {
    use curve25519_dalek::scalar::Scalar;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(scalar.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Scalar::from_bytes_mod_order(bytes))
    }
}

pub mod participant_serde {
    use frost_dalek::Participant;
    use serde::de::Error;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S>(participant: &Participant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unimplemented!("Participant is not serializable because the Nizk isn't");
        serializer.serialize_none()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Participant, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!("Participant is not serializable because the Nizk isn't");
        Err(Error::custom("Participant is not serializable"))
    }
}

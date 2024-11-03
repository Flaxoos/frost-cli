use curve25519_dalek::scalar::Scalar;
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
    use serde::de::{self, Deserializer, SeqAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::Serializer;
    use std::mem::size_of;
    use std::ptr;
    use frost_dalek::signature::PartialThresholdSignature;

    /// Custom serialization for `PartialThresholdSignature`
    pub fn serialize<S>(sig: &PartialThresholdSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PartialThresholdSignature", 2)?;

        state.serialize_field("index", &sig.index)?;

        let scalar_bytes = unsafe {
            std::slice::from_raw_parts(&sig.z as *const _ as *const u8, size_of::<Scalar>())
        };
        state.serialize_field("z", &scalar_bytes)?;

        state.end()
    }

    /// Custom deserialization for `PartialThresholdSignature`
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PartialThresholdSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            index: u32,
            z: Vec<u8>,
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.z.len() != size_of::<Scalar>() {
            return Err(de::Error::custom(
                "Invalid byte length for Scalar in PartialThresholdSignature",
            ));
        }

        let z = unsafe { ptr::read(helper.z.as_ptr() as *const Scalar) };

        Ok(PartialThresholdSignature {
            index: helper.index,
            z,
        })
    }
}

#[cfg(test)]
mod tests {
    use frost_dalek::signature::PartialThresholdSignature;
    use super::*;
    use rand::rngs::OsRng;
    use serde_json;

    #[test]
    fn test_serialize_deserialize_partial_threshold_signature() {
        // Generate a random Scalar for `z`
        let z = Scalar::random(&mut OsRng);
        let index = 42;

        let original_sig = PartialThresholdSignature { index, z };

        let wrapper = PartialThresholdSignatureWrapper(original_sig);

        let serialized = serde_json::to_string(&wrapper).expect("Serialization failed");

        let deserialized: PartialThresholdSignatureWrapper =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(index, deserialized.0.index);
        assert_eq!(z, deserialized.0.z);
    }
}

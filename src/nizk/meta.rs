use crate::protocol::reference::ReferenceProfile;

#[derive(Debug, Clone)]
pub struct SpartanBrakedownProofMeta {
    pub reference_profile: ReferenceProfile,
    pub context_fingerprint: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPublicMeta {
    pub reference_profile: ReferenceProfile,
    pub context_fingerprint: [u8; 32],
}


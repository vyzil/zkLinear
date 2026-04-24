use merlin::Transcript;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolReference {
    Spartan2Like = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcsReference {
    LcpcBrakedownLike = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceProfile {
    pub protocol: ProtocolReference,
    pub pcs: PcsReference,
}

impl ReferenceProfile {
    pub const fn dual_reference_default() -> Self {
        Self {
            protocol: ProtocolReference::Spartan2Like,
            pcs: PcsReference::LcpcBrakedownLike,
        }
    }
}

pub const DUAL_REFERENCE_PROFILE: ReferenceProfile = ReferenceProfile::dual_reference_default();

pub fn append_reference_profile_to_transcript(tr: &mut Transcript, profile: &ReferenceProfile) {
    debug_assert_eq!(profile.protocol, ProtocolReference::Spartan2Like);
    debug_assert_eq!(profile.pcs, PcsReference::LcpcBrakedownLike);

    let protocol_tag: &[u8] = b"protocol:spartan2-like";
    let pcs_tag: &[u8] = b"pcs:lcpc-brakedown-like";

    tr.append_message(b"reference_protocol", protocol_tag);
    tr.append_message(b"reference_pcs", pcs_tag);
}

use merlin::Transcript;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolReference {
    Spartan2Like,
    ExperimentalAlt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcsReference {
    LcpcBrakedownLike,
    ExperimentalAlt,
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
    let protocol_tag: &[u8] = match profile.protocol {
        ProtocolReference::Spartan2Like => b"protocol:spartan2-like",
        ProtocolReference::ExperimentalAlt => b"protocol:experimental-alt",
    };
    let pcs_tag: &[u8] = match profile.pcs {
        PcsReference::LcpcBrakedownLike => b"pcs:lcpc-brakedown-like",
        PcsReference::ExperimentalAlt => b"pcs:experimental-alt",
    };

    tr.append_message(b"reference_protocol", protocol_tag);
    tr.append_message(b"reference_pcs", pcs_tag);
}

//! ADR-322 authenticated sensor datagram envelope.
//!
//! Authentication is deliberately outside each vendor decoder so ESP32,
//! Realtek, MediaTek, Qualcomm, and canonical vendor payloads share the same
//! identity, freshness, and replay boundary.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAGIC: [u8; 4] = *b"RVT1";
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 8 + 8 + 4;
const SIGNATURE_LEN: usize = 64;
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// Confirm that an authenticated source label agrees with the inner wire
/// format. Prevents a valid key enrolled for one decoder from being used to
/// smuggle a payload into another decoder's authority domain.
pub fn source_matches_payload(source: SourceKind, payload: &[u8]) -> bool {
    if source == SourceKind::VendorRf {
        return payload.first() == Some(&b'{');
    }
    if source == SourceKind::WindowsWifi {
        // Windows Wi-Fi observations are collected locally, never accepted on
        // the UDP boundary.
        return false;
    }
    let Some(magic) = payload
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
    else {
        return false;
    };
    match source {
        SourceKind::Esp32 => matches!(
            magic,
            0xC511_0001
                | 0xC511_0002
                | 0xC511_0003
                | 0xC511_0004
                | 0xC511_0005
                | 0xC511_0006
                | 0xC511_0007
                | 0xC511_A110
        ),
        SourceKind::Realtek => magic == wifi_densepose_hardware::rtl8720f::RTL8720F_RADAR_MAGIC,
        SourceKind::Mediatek => magic == wifi_densepose_hardware::mediatek_csi::MEDIATEK_CSI_MAGIC,
        SourceKind::Qualcomm => magic == wifi_densepose_hardware::qualcomm_csi::QUALCOMM_CSI_MAGIC,
        SourceKind::RealtekCsi => magic == wifi_densepose_hardware::realtek_csi::RAC1_MAGIC,
        SourceKind::VendorRf | SourceKind::WindowsWifi => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum SourceKind {
    Esp32 = 1,
    /// RTL8720F FMCW radar (ADR-263/264) — NOT RTL8721Dx CSI, see `RealtekCsi`.
    Realtek = 2,
    Mediatek = 3,
    Qualcomm = 4,
    VendorRf = 5,
    WindowsWifi = 6,
    /// RTL8721Dx (AmebaDplus) 1x1 CSI (ADR-323). Added after the original five
    /// sources; do not renumber the existing discriminants.
    RealtekCsi = 7,
}

impl TryFrom<u8> for SourceKind {
    type Error = EnvelopeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Esp32),
            2 => Ok(Self::Realtek),
            3 => Ok(Self::Mediatek),
            4 => Ok(Self::Qualcomm),
            5 => Ok(Self::VendorRf),
            6 => Ok(Self::WindowsWifi),
            7 => Ok(Self::RealtekCsi),
            _ => Err(EnvelopeError::UnknownSource(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDatagram {
    pub source: SourceKind,
    pub node_id: u8,
    pub sequence: u64,
    pub timestamp_unix_ms: i64,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("not an ADR-322 authenticated envelope")]
    NotEnvelope,
    #[error("authenticated envelope is truncated")]
    Truncated,
    #[error("unsupported authenticated envelope version {0}")]
    Version(u8),
    #[error("unknown source kind {0}")]
    UnknownSource(u8),
    #[error("reserved authenticated-envelope byte must be zero")]
    Reserved,
    #[error("payload length {0} exceeds the bounded maximum")]
    PayloadTooLarge(usize),
    #[error("authenticated envelope length does not match its payload length")]
    LengthMismatch,
    #[error("sensor identity is not enrolled")]
    UnknownIdentity,
    #[error("Ed25519 signature verification failed")]
    BadSignature,
    #[error("sensor timestamp is outside the configured freshness window")]
    Stale,
    #[error("sensor sequence is not strictly increasing")]
    Replay,
    #[error("invalid Ed25519 public key")]
    BadPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    source: SourceKind,
    node_id: u8,
}

struct Enrollment {
    key: VerifyingKey,
    last_sequence: Option<u64>,
}

/// Per-device asymmetric verifier with freshness and replay state.
pub struct DatagramVerifier {
    enrolled: BTreeMap<Identity, Enrollment>,
    max_age_ms: i64,
    max_future_ms: i64,
}

impl DatagramVerifier {
    pub fn new(max_age_ms: i64, max_future_ms: i64) -> Self {
        Self {
            enrolled: BTreeMap::new(),
            max_age_ms: max_age_ms.max(0),
            max_future_ms: max_future_ms.max(0),
        }
    }

    pub fn enroll(
        &mut self,
        source: SourceKind,
        node_id: u8,
        public_key: [u8; 32],
    ) -> Result<(), EnvelopeError> {
        let key = VerifyingKey::from_bytes(&public_key).map_err(|_| EnvelopeError::BadPublicKey)?;
        self.enrolled.insert(
            Identity { source, node_id },
            Enrollment {
                key,
                last_sequence: None,
            },
        );
        Ok(())
    }

    pub fn verify(
        &mut self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<AuthenticatedDatagram, EnvelopeError> {
        if bytes.len() < 4 || bytes[..4] != MAGIC {
            return Err(EnvelopeError::NotEnvelope);
        }
        if bytes.len() < HEADER_LEN + SIGNATURE_LEN {
            return Err(EnvelopeError::Truncated);
        }
        if bytes[4] != VERSION {
            return Err(EnvelopeError::Version(bytes[4]));
        }
        let source = SourceKind::try_from(bytes[5])?;
        let node_id = bytes[6];
        if bytes[7] != 0 {
            return Err(EnvelopeError::Reserved);
        }
        let sequence = u64::from_le_bytes(bytes[8..16].try_into().expect("bounded header"));
        let timestamp_unix_ms =
            i64::from_le_bytes(bytes[16..24].try_into().expect("bounded header"));
        let payload_len =
            u32::from_le_bytes(bytes[24..28].try_into().expect("bounded header")) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::PayloadTooLarge(payload_len));
        }
        let signed_len = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(EnvelopeError::PayloadTooLarge(payload_len))?;
        if bytes.len() != signed_len + SIGNATURE_LEN {
            return Err(EnvelopeError::LengthMismatch);
        }

        let enrollment = self
            .enrolled
            .get_mut(&Identity { source, node_id })
            .ok_or(EnvelopeError::UnknownIdentity)?;
        let signature =
            Signature::from_slice(&bytes[signed_len..]).map_err(|_| EnvelopeError::BadSignature)?;
        enrollment
            .key
            .verify(&bytes[..signed_len], &signature)
            .map_err(|_| EnvelopeError::BadSignature)?;

        let age = now_unix_ms.saturating_sub(timestamp_unix_ms);
        let future = timestamp_unix_ms.saturating_sub(now_unix_ms);
        if age > self.max_age_ms || future > self.max_future_ms {
            return Err(EnvelopeError::Stale);
        }
        if enrollment
            .last_sequence
            .is_some_and(|last| sequence <= last)
        {
            return Err(EnvelopeError::Replay);
        }
        enrollment.last_sequence = Some(sequence);

        Ok(AuthenticatedDatagram {
            source,
            node_id,
            sequence,
            timestamp_unix_ms,
            payload: bytes[HEADER_LEN..signed_len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn envelope(
        key: &SigningKey,
        source: SourceKind,
        node_id: u8,
        sequence: u64,
        timestamp: i64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&[VERSION, source as u8, node_id, 0]);
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&timestamp.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&key.sign(&out).to_bytes());
        out
    }

    #[test]
    fn verifies_ed25519_and_returns_exact_payload() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut verifier = DatagramVerifier::new(5_000, 500);
        verifier
            .enroll(SourceKind::Esp32, 3, key.verifying_key().to_bytes())
            .unwrap();
        let bytes = envelope(&key, SourceKind::Esp32, 3, 10, 1_000, b"csi");
        let opened = verifier.verify(&bytes, 1_100).unwrap();
        assert_eq!(opened.payload, b"csi");
        assert_eq!(opened.sequence, 10);
    }

    #[test]
    fn tamper_replay_stale_and_unknown_identity_fail_closed() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut verifier = DatagramVerifier::new(100, 10);
        verifier
            .enroll(SourceKind::Qualcomm, 4, key.verifying_key().to_bytes())
            .unwrap();

        let good = envelope(&key, SourceKind::Qualcomm, 4, 1, 1_000, b"frame");
        verifier.verify(&good, 1_000).unwrap();
        assert_eq!(verifier.verify(&good, 1_000), Err(EnvelopeError::Replay));

        let mut tampered = envelope(&key, SourceKind::Qualcomm, 4, 2, 1_000, b"frame");
        tampered[HEADER_LEN] ^= 1;
        assert_eq!(
            verifier.verify(&tampered, 1_000),
            Err(EnvelopeError::BadSignature)
        );

        let stale = envelope(&key, SourceKind::Qualcomm, 4, 2, 1_000, b"frame");
        assert_eq!(verifier.verify(&stale, 2_000), Err(EnvelopeError::Stale));

        let unknown = envelope(&key, SourceKind::Realtek, 4, 2, 1_000, b"frame");
        assert_eq!(
            verifier.verify(&unknown, 1_000),
            Err(EnvelopeError::UnknownIdentity)
        );
    }

    #[test]
    fn malformed_lengths_never_allocate_from_wire_value() {
        let mut bytes = Vec::from(MAGIC);
        bytes.resize(HEADER_LEN + SIGNATURE_LEN, 0);
        bytes[4] = VERSION;
        bytes[5] = SourceKind::Esp32 as u8;
        bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut verifier = DatagramVerifier::new(1, 1);
        assert!(matches!(
            verifier.verify(&bytes, 0),
            Err(EnvelopeError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn source_label_must_match_inner_decoder() {
        let mut esp = 0xC511_0001u32.to_le_bytes().to_vec();
        esp.resize(20, 0);
        assert!(source_matches_payload(SourceKind::Esp32, &esp));
        assert!(!source_matches_payload(SourceKind::Qualcomm, &esp));
        assert!(source_matches_payload(SourceKind::VendorRf, b"{}"));
        assert!(!source_matches_payload(SourceKind::WindowsWifi, b"{}"));
    }
}

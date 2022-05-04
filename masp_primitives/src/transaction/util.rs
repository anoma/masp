use borsh::maybestd::io::{Error, ErrorKind};
use borsh::BorshDeserialize;
use group::GroupEncoding;
use std::convert::TryInto;

pub fn deserialize_extended_point(
    buf: &mut &[u8],
) -> borsh::maybestd::io::Result<jubjub::ExtendedPoint> {
    Option::from(jubjub::ExtendedPoint::from_bytes(
        &BorshDeserialize::deserialize(buf)?,
    ))
    .ok_or_else(|| Error::from(ErrorKind::InvalidData))
}

pub fn deserialize_scalar(buf: &mut &[u8]) -> borsh::maybestd::io::Result<bls12_381::Scalar> {
    Option::from(bls12_381::Scalar::from_bytes(
        &BorshDeserialize::deserialize(buf)?,
    ))
    .ok_or_else(|| Error::from(ErrorKind::InvalidData))
}

pub fn deserialize_array<const N: usize>(buf: &mut &[u8]) -> borsh::maybestd::io::Result<[u8; N]> {
    let errf = || Error::from(ErrorKind::UnexpectedEof);
    let data = buf.get(0..N).ok_or_else(errf)?.try_into().unwrap();
    *buf = &buf[N..];
    Ok(data)
}

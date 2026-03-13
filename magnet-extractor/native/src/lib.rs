use std::collections::BTreeMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

struct ParseResult {
    value: Value,
    end: usize,
    info_range: Option<(usize, usize)>,
}

#[pyfunction]
fn extract_torrent_metadata(
    payload: &[u8],
) -> PyResult<(String, bool, bool, Option<String>, Option<String>)> {
    let info_bytes = extract_info_slice(payload)?;
    let info = decode_dict(info_bytes)?;
    let dn =
        pick_name(&info)?.ok_or_else(|| PyValueError::new_err("torrent missing display name"))?;

    let has_v1 = info.contains_key(b"pieces".as_slice());
    let has_v2 = matches!(info.get(b"meta version".as_slice()), Some(Value::Int(2)))
        && info.contains_key(b"file tree".as_slice());
    if !has_v1 && !has_v2 {
        return Err(PyValueError::new_err(
            "torrent has neither v1 nor v2 metadata",
        ));
    }

    let btih = has_v1.then(|| {
        let digest = Sha1::digest(info_bytes);
        hex_lower(digest.as_ref())
    });
    let btmh = has_v2.then(|| {
        let digest = Sha256::digest(info_bytes);
        format!("1220{}", hex_lower(digest.as_ref()))
    });

    Ok((dn, has_v1, has_v2, btih, btmh))
}

#[pymodule]
fn magnet_extractor_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_torrent_metadata, m)?)?;
    Ok(())
}

fn extract_info_slice(payload: &[u8]) -> PyResult<&[u8]> {
    if payload.first() != Some(&b'd') {
        return Err(PyValueError::new_err(
            "torrent payload must be a dictionary",
        ));
    }

    let result = parse_dict(payload, 0, true)?;
    if result.end != payload.len() {
        return Err(PyValueError::new_err(
            "trailing bytes after torrent payload",
        ));
    }

    let (start, end) = result
        .info_range
        .ok_or_else(|| PyValueError::new_err("torrent missing info dictionary"))?;
    Ok(&payload[start..end])
}

fn decode_dict(payload: &[u8]) -> PyResult<BTreeMap<Vec<u8>, Value>> {
    let result = parse_any(payload, 0)?;
    if result.end != payload.len() {
        return Err(PyValueError::new_err("trailing bytes after bencoded value"));
    }

    match result.value {
        Value::Dict(items) => Ok(items),
        _ => Err(PyValueError::new_err("torrent info must be a dictionary")),
    }
}

fn parse_any(payload: &[u8], index: usize) -> PyResult<ParseResult> {
    if index >= payload.len() {
        return Err(PyValueError::new_err("unexpected end of bencoded data"));
    }

    match payload[index] {
        b'i' => parse_int(payload, index),
        b'l' => parse_list(payload, index),
        b'd' => parse_dict(payload, index, false),
        b'0'..=b'9' => parse_bytes(payload, index),
        _ => Err(PyValueError::new_err("invalid bencode token")),
    }
}

fn parse_int(payload: &[u8], index: usize) -> PyResult<ParseResult> {
    let end = payload[index + 1..]
        .iter()
        .position(|&byte| byte == b'e')
        .map(|offset| index + 1 + offset)
        .ok_or_else(|| PyValueError::new_err("unterminated integer"))?;

    let token = &payload[index + 1..end];
    if token.is_empty() {
        return Err(PyValueError::new_err("empty integer"));
    }

    let negative = token.first() == Some(&b'-');
    let digits = if negative { &token[1..] } else { token };
    if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(PyValueError::new_err("invalid integer digits"));
    }
    if digits.starts_with(b"0") && digits.len() > 1 {
        return Err(PyValueError::new_err("invalid integer leading zero"));
    }
    if negative && digits == b"0" {
        return Err(PyValueError::new_err("invalid negative zero"));
    }

    let token_str =
        std::str::from_utf8(token).map_err(|_| PyValueError::new_err("invalid integer digits"))?;
    let value = token_str
        .parse::<i64>()
        .map_err(|_| PyValueError::new_err("invalid integer digits"))?;
    Ok(ParseResult {
        value: Value::Int(value),
        end: end + 1,
        info_range: None,
    })
}

fn parse_bytes(payload: &[u8], index: usize) -> PyResult<ParseResult> {
    let colon = payload[index..]
        .iter()
        .position(|&byte| byte == b':')
        .map(|offset| index + offset)
        .ok_or_else(|| PyValueError::new_err("unterminated byte string length"))?;

    let length_token = &payload[index..colon];
    if length_token.is_empty() || !length_token.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(PyValueError::new_err("invalid byte string length"));
    }
    if length_token.starts_with(b"0") && length_token.len() > 1 {
        return Err(PyValueError::new_err("invalid byte string leading zero"));
    }

    let length_str = std::str::from_utf8(length_token)
        .map_err(|_| PyValueError::new_err("invalid byte string length"))?;
    let length = length_str
        .parse::<usize>()
        .map_err(|_| PyValueError::new_err("invalid byte string length"))?;
    let start = colon + 1;
    let end = start + length;
    if end > payload.len() {
        return Err(PyValueError::new_err("byte string overruns payload"));
    }

    Ok(ParseResult {
        value: Value::Bytes(payload[start..end].to_vec()),
        end,
        info_range: None,
    })
}

fn parse_list(payload: &[u8], mut index: usize) -> PyResult<ParseResult> {
    let mut items = Vec::new();
    index += 1;

    loop {
        if index >= payload.len() {
            return Err(PyValueError::new_err("unterminated list"));
        }
        if payload[index] == b'e' {
            return Ok(ParseResult {
                value: Value::List(items),
                end: index + 1,
                info_range: None,
            });
        }

        let result = parse_any(payload, index)?;
        items.push(result.value);
        index = result.end;
    }
}

fn parse_dict(payload: &[u8], mut index: usize, capture_info: bool) -> PyResult<ParseResult> {
    let mut items = BTreeMap::new();
    let mut info_range = None;
    let mut previous_key: Option<Vec<u8>> = None;
    index += 1;

    loop {
        if index >= payload.len() {
            return Err(PyValueError::new_err("unterminated dictionary"));
        }
        if payload[index] == b'e' {
            return Ok(ParseResult {
                value: Value::Dict(items),
                end: index + 1,
                info_range,
            });
        }

        let key_result = parse_bytes(payload, index)?;
        let key = match key_result.value {
            Value::Bytes(bytes) => bytes,
            _ => unreachable!(),
        };
        index = key_result.end;

        if let Some(previous) = previous_key.as_deref() {
            if key.as_slice() <= previous {
                return Err(PyValueError::new_err(
                    "dictionary keys must be strictly sorted",
                ));
            }
        }
        previous_key = Some(key.clone());

        let value_start = index;
        let value_result = parse_any(payload, index)?;
        if capture_info && key == b"info" {
            if !matches!(&value_result.value, Value::Dict(_)) {
                return Err(PyValueError::new_err("torrent info must be a dictionary"));
            }
            info_range = Some((value_start, value_result.end));
        }

        index = value_result.end;
        items.insert(key, value_result.value);
    }
}

fn pick_name(info: &BTreeMap<Vec<u8>, Value>) -> PyResult<Option<String>> {
    if let Some(value) = info.get(b"name.utf-8".as_slice()) {
        return decode_text(value).map(Some);
    }
    if let Some(value) = info.get(b"name".as_slice()) {
        return decode_text(value).map(Some);
    }
    Ok(None)
}

fn decode_text(value: &Value) -> PyResult<String> {
    match value {
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| PyValueError::new_err("torrent name must be valid UTF-8")),
        _ => Err(PyValueError::new_err("torrent name must be a byte string")),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

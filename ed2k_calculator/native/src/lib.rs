use md4::{Digest, Md4};
use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use std::cmp;
use std::fs::File;
use std::io::{self, Read};

const CHUNK: usize = 9_728_000;

fn md4_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn read_exact_len(file: &mut File, size: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; size];
    let mut offset = 0usize;

    while offset < size {
        let read = file.read(&mut out[offset..])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading stream",
            ));
        }
        offset += read;
    }

    Ok(out)
}

#[pyfunction]
fn md4_hex(data: &[u8]) -> String {
    hex::encode_upper(md4_digest(data))
}

#[pyfunction]
fn ed2k115_file_hex(py: Python<'_>, path: &str, file_size: u64) -> PyResult<String> {
    let path_owned = path.to_owned();
    py.allow_threads(move || ed2k115_file_hex_impl(&path_owned, file_size))
        .map_err(|e| PyIOError::new_err(e.to_string()))
}

fn ed2k115_file_hex_impl(path: &str, file_size: u64) -> io::Result<String> {
    let mut file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to open file '{path}': {e}")))?;

    if file_size < CHUNK as u64 {
        let data = read_exact_len(&mut file, file_size as usize)?;
        let first = md4_digest(&data);
        return Ok(hex::encode_upper(md4_digest(&first)));
    }

    let chunk_count = file_size.div_ceil(CHUNK as u64) as usize;
    let mut chunk_digests = Vec::with_capacity((chunk_count + 1) * 16);
    let mut remaining = file_size;

    while remaining > 0 {
        let to_read = cmp::min(CHUNK as u64, remaining) as usize;
        let chunk = read_exact_len(&mut file, to_read)?;
        chunk_digests.extend_from_slice(&md4_digest(&chunk));
        remaining -= to_read as u64;
    }

    if file_size % CHUNK as u64 == 0 {
        chunk_digests.extend_from_slice(&md4_digest(b""));
    }

    Ok(hex::encode_upper(md4_digest(&chunk_digests)))
}

#[pymodule]
fn ed2k115_native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(md4_hex, m)?)?;
    m.add_function(wrap_pyfunction!(ed2k115_file_hex, m)?)?;
    Ok(())
}

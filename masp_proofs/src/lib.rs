//! *MASP circuits and proofs.*
//!
//! `masp_proofs` contains the zk-SNARK circuits used by MASP based on Zcash Sapling, and the APIs for creating
//! and verifying proofs.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey};
use bls12_381::Bls12;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

#[cfg(feature = "directories")]
use directories::BaseDirs;
#[cfg(feature = "directories")]
use std::path::PathBuf;

pub mod circuit;
pub mod constants;
pub mod hashreader;
pub mod sapling;

// #[cfg(feature = "embed-verifying-key")]
// pub mod params;
#[cfg(any(feature = "local-prover", feature = "bundled-prover"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "local-prover", feature = "bundled-prover")))
)]
pub mod prover;

// Circuit names
#[cfg(feature = "local-prover")]
const MASP_SPEND_NAME: &str = "masp-spend.params";
#[cfg(feature = "local-prover")]
const MASP_OUTPUT_NAME: &str = "masp-output.params";
#[cfg(feature = "local-prover")]
const MASP_CONVERT_NAME: &str = "masp-convert.params";

// Circuit hashes
const MASP_SPEND_HASH: &str = "5523057113d7daa078714f9859ea03da3c959f4fe3756a0ace4eb25f7cf41d1e21099dac768c2e0045400fee03c1f8bc14eeac2190c3f282e0092419d3b967e5";
const MASP_OUTPUT_HASH: &str = "89fe551ad6c0281aebb857eb203dbf35854979503d374c83b12512dcd737e12a255869a34e3ff0f6609b78accc81ea5f5e94202e124a590730494eeeee86e755";
const MASP_CONVERT_HASH: &str = "7a6b038c45ddd841e500484b1c72fa021d874de5a83bf8bce6c0fd8f3c63d491243495df2661682333728a8b14c439985b63b0d6ed61044286e2f86734d66d9b";
// Circuit parameter file sizes
const MASP_SPEND_BYTES: u64 = 47958396;
const MASP_CONVERT_BYTES: u64 = 47958396;
const MASP_OUTPUT_BYTES: u64 = 3592860;

#[cfg(feature = "download-params")]
const DOWNLOAD_URL: &str = "https://github.com/anoma/masp/blob/test_parameters";

/// Returns the default folder that the MASP proving parameters are located in.
#[cfg(feature = "directories")]
#[cfg_attr(docsrs, doc(cfg(feature = "directories")))]
pub fn default_params_folder() -> Option<PathBuf> {
    BaseDirs::new().map(|base_dirs| {
        if cfg!(any(windows, target_os = "macos")) {
            base_dirs.data_dir().join("MASPParams")
        } else {
            base_dirs.home_dir().join(".masp-params")
        }
    })
}

/// Download the MASP Sapling parameters, storing them in the default location.
/// Always checks the sizes and hashes of the files, even if they didn't need to be downloaded.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
///
/// Use `timeout` to set a timeout in seconds for each file download.
/// If `timeout` is `None`, a timeout can be set using the `MINREQ_TIMEOUT` environmental variable.
///
/// Returns the paths to the downloaded files.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_sapling_parameters(
    timeout: Option<u64>,
) -> Result<SaplingParameterPaths, minreq::Error> {
    let spend = fetch_params(
        SAPLING_SPEND_NAME,
        SAPLING_SPEND_HASH,
        SAPLING_SPEND_BYTES,
        timeout,
    )?;
    let output = fetch_params(
        SAPLING_OUTPUT_NAME,
        SAPLING_OUTPUT_HASH,
        SAPLING_OUTPUT_BYTES,
        timeout,
    )?;
    let convert = fetch_params(
        SAPLING_CONVERT_NAME,
        SAPLING_CONVERT_HASH,
        SAPLING_CONVERT_BYTES,
        timeout,
    )?;

    Ok(SaplingParameterPaths { spend, output, convert })
}

/// Download the specified parameters if needed, and store them in the default location.
/// Always checks the size and hash of the file, even if it didn't need to be downloaded.
///
/// See [`download_sapling_parameters`] for details.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
fn fetch_params(
    name: &str,
    expected_hash: &str,
    expected_bytes: u64,
    timeout: Option<u64>,
) -> Result<PathBuf, minreq::Error> {
    // Ensure that the default MASP parameters location exists.
    let params_dir = default_params_folder().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "Could not load default params folder")
    })?;
    std::fs::create_dir_all(&params_dir)?;

    let params_path = params_dir.join(name);

    // Download parameters if needed.
    // TODO: use try_exists when it stabilises, to exit early on permissions errors (#83186)
    if !params_path.exists() {
        let result = stream_params_downloads_to_disk(
            &params_path,
            name,
            expected_hash,
            expected_bytes,
            timeout,
        );

        // Remove the file on error, and return the download or hash error.
        if result.is_err() {
            let _ = std::fs::remove_file(&params_path);
            result?;
        }
    } else {
        // TODO: avoid reading the files twice
        // Either:
        // - return Ok if the paths exist, or
        // - always load and return the parameters, for newly downloaded and existing files.

        let file_path_string = params_path.to_string_lossy();

        // Check the file size is correct before hashing large amounts of data.
        verify_file_size(&params_path, expected_bytes, name, &file_path_string).expect(
            "parameter file size is not correct, \
             please clean your MASP parameters directory and re-run `fetch-params`.",
        );

        // Read the file to verify the hash,
        // discarding bytes after they're hashed.
        let params_file = File::open(&params_path)?;
        let params_file = BufReader::with_capacity(1024 * 1024, params_file);
        let params_file = hashreader::HashReader::new(params_file);

        verify_hash(
            params_file,
            io::sink(),
            expected_hash,
            expected_bytes,
            name,
            &file_path_string,
        )?;
    }

    Ok(params_path)
}

/// Download the specified parameter file, stream it to `params_path`, and check its hash.
///
/// See [`download_sapling_parameters`] for details.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
fn stream_params_downloads_to_disk(
    params_path: &Path,
    name: &str,
    expected_hash: &str,
    expected_bytes: u64,
    timeout: Option<u64>,
) -> Result<(), minreq::Error> {
    use downloadreader::ResponseLazyReader;
    use std::io::{BufWriter, Read};

    // Fail early if the directory isn't writeable.
    let new_params_file = File::create(params_path)?;
    let new_params_file = BufWriter::with_capacity(1024 * 1024, new_params_file);

    // Set up the download requests.
    //
    // It's necessary for us to host these files in two parts,
    // because of CloudFlare's maximum cached file size limit of 512 MB.
    // The files must fit in the cache to prevent "denial of wallet" attacks.
    let params_url_1 = format!("{}/{}.part.1", DOWNLOAD_URL, name);
    // TODO: skip empty part.2 files when downloading sapling spend and sapling output
    let params_url_2 = format!("{}/{}.part.2", DOWNLOAD_URL, name);

    let mut params_download_1 = minreq::get(&params_url_1);
    let mut params_download_2 = minreq::get(&params_url_2);
    if let Some(timeout) = timeout {
        params_download_1 = params_download_1.with_timeout(timeout);
        params_download_2 = params_download_2.with_timeout(timeout);
    }

    // Download the responses and write them to a new file,
    // verifying the hash as bytes are read.
    let params_download_1 = ResponseLazyReader::from(params_download_1);
    let params_download_2 = ResponseLazyReader::from(params_download_2);

    // Limit the download size to avoid DoS.
    // This also avoids launching the second request, if the first request provides enough bytes.
    let params_download = params_download_1
        .chain(params_download_2)
        .take(expected_bytes);
    let params_download = BufReader::with_capacity(1024 * 1024, params_download);
    let params_download = hashreader::HashReader::new(params_download);

    verify_hash(
        params_download,
        new_params_file,
        expected_hash,
        expected_bytes,
        name,
        &format!("{} + {}", params_url_1, params_url_2),
    )?;

    Ok(())
}

/// MASP Sapling groth16 circuit parameters.
#[allow(clippy::upper_case_acronyms)]
pub struct MASPParameters {
    pub spend_params: Parameters<Bls12>,
    pub spend_vk: PreparedVerifyingKey<Bls12>,
    pub output_params: Parameters<Bls12>,
    pub output_vk: PreparedVerifyingKey<Bls12>,
    pub convert_params: Parameters<Bls12>,
    pub convert_vk: PreparedVerifyingKey<Bls12>,
}

/// Load the specified parameters, checking the sizes and hashes of the files.
///
/// Returns the loaded parameters.
pub fn load_parameters(
    spend_path: &Path,
    output_path: &Path,
    convert_path: &Path,
) -> MASPParameters {
        // Check the file sizes are correct before hashing large amounts of data.
        verify_file_size(
            spend_path,
            SAPLING_SPEND_BYTES,
            "masp spend",
            &spend_path.to_string_lossy(),
        )
        .expect(
            "parameter file size is not correct, \
             please clean your MASP parameters directory and re-run `fetch-params`.",
        );
    
        verify_file_size(
            output_path,
            SAPLING_OUTPUT_BYTES,
            "masp output",
            &output_path.to_string_lossy(),
        )
        .expect(
            "parameter file size is not correct, \
             please clean your MASP parameters directory and re-run `fetch-params`.",
        );
        verify_file_size(
            convert_path,
            SAPLING_CONVERT_BYTES,
            "masp convert",
            &convert_path.to_string_lossy(),
        )
        .expect(
            "parameter file size is not correct, \
             please clean your MASP parameters directory and re-run `fetch-params`.",
        );
    // Load from each of the paths
    let spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let output_fs = File::open(output_path).expect("couldn't load Sapling output parameters file");
    let convert_fs = File::open(convert_path).expect("couldn't load convert parameters file");

    parse_parameters(
        BufReader::with_capacity(1024 * 1024, spend_fs),
        BufReader::with_capacity(1024 * 1024, output_fs),
        BufReader::with_capacity(1024 * 1024, convert_fs),
    )
}

/// Parse Bls12 keys from bytes as serialized by [`Parameters::write`].
///
/// This function will panic if it encounters unparseable data.
pub fn parse_parameters<R: io::Read>(spend_fs: R, output_fs: R, convert_fs: R) -> MASPParameters {
    let mut spend_fs = hashreader::HashReader::new(spend_fs);
    let mut output_fs = hashreader::HashReader::new(output_fs);
    let mut convert_fs = hashreader::HashReader::new(convert_fs);

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize MASP spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize MASP output parameters file");
    let convert_params = Parameters::<Bls12>::read(&mut convert_fs, false)
        .expect("couldn't deserialize MASP convert parameters file");

    // There is extra stuff (the transcript) at the end of the parameter file which is
    // used to verify the parameter validity, but we're not interested in that. We do
    // want to read it, though, so that the BLAKE2b computed afterward is consistent
    // with `b2sum` on the files.
    let mut sink = io::sink();
    io::copy(&mut spend_fs, &mut sink)
        .expect("couldn't finish reading MASP spend parameter file");
    io::copy(&mut output_fs, &mut sink)
        .expect("couldn't finish reading MASP output parameter file");
    io::copy(&mut convert_fs, &mut sink)
    .expect("couldn't finish reading MASP convert parameter file");

    if spend_fs.into_hash() != MASP_SPEND_HASH {
        panic!("MASP spend parameter file is not correct, please clean your `~/.masp-params/` and re-run `fetch-params`.");
    }

    if output_fs.into_hash() != MASP_OUTPUT_HASH {
        panic!("MASP output parameter file is not correct, please clean your `~/.masp-params/` and re-run `fetch-params`.");
    }

    if convert_fs.into_hash() != MASP_CONVERT_HASH {
        panic!("MASP convert file is not correct, please clean your `~/.masp-params/` and re-run `fetch-params`.");
    }

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);
    let convert_vk = prepare_verifying_key(&convert_params.vk);

    MASPParameters {
        spend_params,
        spend_vk,
        output_params,
        output_vk,
        convert_params,
        convert_vk,
    }
}

/// Check if the size of the file at `params_path` matches `expected_bytes`,
/// using filesystem metadata.
///
/// Returns an error containing `name` and `params_source` on failure.
fn verify_file_size(
    params_path: &Path,
    expected_bytes: u64,
    name: &str,
    params_source: &str,
) -> Result<(), io::Error> {
    let file_size = std::fs::metadata(params_path)?.len();

    if file_size != expected_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} failed validation:\n\
                 expected: {} bytes,\n\
                 actual:   {} bytes from {:?}",
                name, expected_bytes, file_size, params_source,
            ),
        ));
    }

    Ok(())
}

/// Check if the Blake2b hash from `hash_reader` matches `expected_hash`,
/// while streaming from `hash_reader` into `sink`.
///
/// `hash_reader` can be used to partially read its inner reader's data,
/// before verifying the hash using this function.
///
/// Returns an error containing `name` and `params_source` on failure.
fn verify_hash<R: io::Read, W: io::Write>(
    mut hash_reader: hashreader::HashReader<R>,
    mut sink: W,
    expected_hash: &str,
    expected_bytes: u64,
    name: &str,
    params_source: &str,
) -> Result<(), io::Error> {
    let read_result = io::copy(&mut hash_reader, &mut sink);

    if let Err(read_error) = read_result {
        return Err(io::Error::new(
            read_error.kind(),
            format!(
                "{} failed reading:\n\
                 expected: {} bytes,\n\
                 actual:   {} bytes from {:?},\n\
                 error: {:?}",
                name,
                expected_bytes,
                hash_reader.byte_count(),
                params_source,
                read_error,
            ),
        ));
    }

    let byte_count = hash_reader.byte_count();
    let hash = hash_reader.into_hash();
    if hash != expected_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} failed validation:\n\
                 expected: {} hashing {} bytes,\n\
                 actual:   {} hashing {} bytes from {:?}",
                name, expected_hash, expected_bytes, hash, byte_count, params_source,
            ),
        ));
    }

    Ok(())
}

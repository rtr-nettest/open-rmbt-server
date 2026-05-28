use std::io;
use std::fs::File;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Load a TLS `ServerConfig` from PEM certificate and key files.
///
/// The certificate file may contain a chain (server cert first, then
/// intermediates) — rustls accepts the full chain in one PEM file.
pub fn build_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    // Load certificate chain.
    let cert_file = File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("cannot open cert file '{}': {}", cert_path, e))?;
    let mut cert_reader = io::BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse certs from '{}': {}", cert_path, e))?;

    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!("no certificates found in '{}'", cert_path));
    }

    // Load private key — try PKCS#8 first, then RSA (PKCS#1).
    let key_file = File::open(key_path)
        .map_err(|e| anyhow::anyhow!("cannot open key file '{}': {}", key_path, e))?;
    let mut key_reader = io::BufReader::new(key_file);

    let private_key: PrivateKeyDer<'static> = {
        // Read the file content and try different key formats.
        let key_file2 = File::open(key_path)?;
        let mut kr2 = io::BufReader::new(key_file2);

        if let Some(key) = pkcs8_private_keys(&mut key_reader).next() {
            PrivateKeyDer::Pkcs8(key.map_err(|e| anyhow::anyhow!("bad PKCS8 key: {e}"))?)
        } else if let Some(key) = rsa_private_keys(&mut kr2).next() {
            PrivateKeyDer::Pkcs1(key.map_err(|e| anyhow::anyhow!("bad RSA key: {e}"))?)
        } else {
            return Err(anyhow::anyhow!("no private key found in '{}'", key_path));
        }
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;

    Ok(config)
}

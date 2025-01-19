# Async-Symm-Crypto

A crate that wraps around openssl providing very convenient async interfaces to openssl's symmetric cryptography functions. It is:


[![Crates.io][crates-badge]][crates-url]
[![Crates.io][crates-badge]][crates-url]
[![Docs][docs-badge]][docs-url]
[![Build][actions-badge]][actions-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/badge/crates.io-v0.2.0-f58142
[crates-url]: https://crates.io/crates/async_symm_crypto
[actions-badge]: https://github.com/didoloan/async-symm-crypto/workflows/CI/badge.svg
[actions-url]: https://github.com/didoloan/async-symm-crypto/actions?query=workflow%3ACI+branch%3Amaster
[docs-badge]: https://img.shields.io/badge/docs-passing-cc61e
[docs-url]: https://docs.rs/async_symm_crypto/0.1.0/async_symm_crypto/
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/didoloan/async_symm_crypto/blob/master/LICENSE

[Website](https://github.com/didoloan/async-symm-crypto/blob/master/README.md) |
[API Docs](https://docs.rs/async_symm_crypto/latest)


## Example

Basic example of stream cryptography

Make sure openssl is installed on the operating

```toml
[dependencies]
async_symm_crypto = "0.2.0"
```
Then, on your main.rs:

```rust,no_run
use async_symm_crypto::AsyncEncryption;
use openssl;
use futures::StreamExt;
use std::ops::Deref;
use std::pin::Pin;
use tokio; 

static TEST_STRING:&'static str = "Cryptographic protocols like TLS, SSH, IPsec, and OpenVPN commonly use block cipher algorithms, such as AES, Triple-DES, and Blowfish, to encrypt data between clients and servers. To use such algorithms, the data is broken into fixed-length chunks, called blocks, and each block is encrypted separately according to a mode of operation. Older block ciphers, such as Triple-DES and Blowfish use a block size of 64 bits, whereas AES uses a block size of 128 bits.";
static TEST_KEY: &[u8; 24] = b"266126f0ebb836dbcff05110";

static ENCRYPTED_BASE64: &'static str = "4OLRDw2hg3CyK7II2I6Y2zEHH7LDqw/gQb8kOXEAqT9ULt0Ks66atiVnMgx5yWntPVq8hYREfDMXl0RRac5t8i7ro6zZY46OGUHyC2OvBPnbZPwAfX3hCKiT8BbEhp88XUBB/k2AEiefw9c25MaTp1S121vNub2N5tdOj6dd4SEpz7iB8Hm6V2MdUECVUZ/6a8HMRCLOtD9JSXFSce8/bucO3Ip+rFUP6bKaDzZ5peIRe+MiuHUqt6w1lXS0S8wRov9N8QkQq9/AIcY6qhwpFO7puqYCt7x3mRL1Q9sfS5su3q/NiBLmB8u+4UwnngfBiupjwmkq072iZItefHMpjBRMlzkCw1N0/32XnIi0jFKGVE9SBOMReFxtX0xsh5iRfg/xxtOJui6kV/xe015tjAMonYklWL9xwaueBXJZhcf9xZssmJzx5MR25p6eIoeiO1TQhy3oJiH3/OC3xD7+1ZZJepN8hKx+bTwdZzUxZ/cRjlShrEF0pojauFgunrNNmjdUbaNXa4Uk/LhdHrxci4RH8BKjiuJ0pWULdHh6xDV8cMMS30INDFT0JG4OqZCRFKBtOlSw8VxqQd/mBRSBlZZ6VdsVS2tpyGHurimGvac=";

fn get_text_byte_stream(
) -> impl futures::Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send {
    futures::stream::iter(
        TEST_STRING
        .as_bytes()
        .chunks(16)
        .map(bytes::Bytes::copy_from_slice)
        .map(|x| Ok(x)),
    )
}


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = AsyncEncryption::new(
        openssl::symm::Cipher::des_ede3_cbc(),
        TEST_KEY,
        Some(b"bcff0511"),
    );

    let mut bytes_stream = get_text_byte_stream();

    let mut enc_stream = crypto.encrypt_stream(&mut bytes_stream)?;

    let mut enc_bytes = Vec::new();

    while let Some(Ok(part)) = enc_stream.next().await {
        enc_bytes.extend_from_slice(part.deref());
    }

    assert_eq!(ENCRYPTED_BASE64, &openssl::base64::encode_block(&enc_bytes));
    Ok(())
}
```

## Contributing

:balloon: Contributions are very welcome to improve the project.

## License

This project is licensed under the [MIT license].

[MIT license]: https://github.com/didoloan/async_symm_crypto/blob/master/LICENSE

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, shall be licensed as MIT, without any additional
terms or conditions.

### I'm looking to get hired

If you like my work, please let me know by recommending me for rust jobs.
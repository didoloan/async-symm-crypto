# Async-Symm-Crypto

A crate that wraps around openssl providing very convenient async interfaces to openssl's symmetric cryptography functions. It is:


[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-url]: https://crates.io/crates/async_symm_crypto
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/didoloan/async_symm_crypto/blob/master/LICENSE

[Website](https://github.com/didoloan/async_symm_crypto/blob/master/README.md) |
[API Docs](https://docs.rs/async_symm_crypto/latest)


## Example

Basic example of stream cryptography

Make sure openssl is installed on the operating

```toml
[dependencies]
async_symm_crypto = "0.1.0"
```
Then, on your main.rs:

```rust,no_run
use async_symm_crypto::AsyncEncryption;
use futures::StreamExt;
use std::ops::Deref;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = AsyncEncryption::new(
        openssl::symm::Cipher::des_ede3_cbc(),
        TEST_KEY,
        Some(b"bcff0511"),
    );

    let mut enc_stream = crypto.encrypt_stream(get_text_byte_stream());

    let mut enc_bytes = Vec::new();

    while let Some(Ok(part)) = enc_stream.next().await {
        enc_bytes.extend_from_slice(part.deref());
    }
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
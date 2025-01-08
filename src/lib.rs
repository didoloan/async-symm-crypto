// mod async_decrypt_task;
// mod async_encrypt_task;
mod async_stream_dec_task;
mod async_stream_enc_task;

use std::ops::Deref;
// use async_decrypt_task::AsyncDecryptTask;
// use async_encrypt_task::AsyncEncryptTask;
use async_stream_dec_task::AsyncStreamDecryptTask;
use async_stream_enc_task::AsyncStreamEncryptTask;
use bytes::Bytes;
use futures::{Stream, StreamExt};

pub mod re_exports {
    pub use openssl;
    pub use bytes;
    pub use futures;
}

pub mod prelude {
    pub use crate::AsyncEncryption;
    // pub use crate::AsyncStreamEncryptTask;
    // pub use crate::AsyncStreamDecryptTask;
}

pub struct AsyncEncryption<'a> {
    cypher: openssl::symm::Cipher,
    key: &'a [u8],
    iv: Option<&'a [u8]>,
}

impl<'a> AsyncEncryption<'a> {
    pub fn new(cypher: openssl::symm::Cipher, key: &'a [u8], iv: Option<&'a [u8]>) -> Self {
        Self { cypher, key, iv }
    }

    /// Encrypt a &[u8] returning a decrypted Vec<u8>.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_symm_crypto::AsyncEncryption;
    /// let crypto = AsyncEncryption::new(
    ///     openssl::symm::Cipher::des_ede3_cbc(),
    ///     TEST_KEY, //size varies by cypher
    ///     Some(b"bcff0511"),
    /// );
    /// let enc_bytes:Vec<u8> = crypto.encrypt(TEST_STRING.as_bytes()).await.unwrap();
    /// ```
    ///
    pub async fn encrypt(
        &self,
        bytes_to_encrypt: &'a [u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes_stream = futures::stream::iter(
            bytes_to_encrypt
                .chunks(self.cypher.block_size() * 2)
                .map(Bytes::copy_from_slice)
                .map(Ok),
        );

        let mut stream = self.encrypt_stream(bytes_stream);

        let mut output = Vec::with_capacity(bytes_to_encrypt.len() + self.cypher.block_size());

        while let Some(Ok(part)) = stream.next().await {
            output.extend_from_slice(part.deref());
        }
        Ok(output)
    }

    /// Decrypt a &[u8] returning a decrypted Vec<u8>.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use async_symm_crypto::AsyncEncryption;
    ///
    /// let crypto = AsyncEncryption::new(
    ///     openssl::symm::Cipher::des_ede3_cbc(),
    ///     TEST_KEY,
    ///     Some(b"bcff0511"),
    /// );
    ///
    /// let plain_bytes = crypto
    /// .decrypt(&openssl::base64::decode_block(ENCRYPTED_BASE64).unwrap())
    /// .await
    /// .unwrap();
    /// ```
    ///
    pub async fn decrypt(
        &self,
        bytes_to_decrypt: &'a [u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes_stream = futures::stream::iter(
            bytes_to_decrypt
                .chunks(self.cypher.block_size() * 2)
                .map(Bytes::copy_from_slice)
                .map(Ok),
        );

        let mut stream = self.decrypt_stream(bytes_stream);

        let mut output = Vec::with_capacity(bytes_to_decrypt.len() + self.cypher.block_size());

        while let Some(Ok(part)) = stream.next().await {
            output.extend_from_slice(part.deref());
        }

        Ok(output)
    }

    /// Encrypt a Fallible Stream returning the encrypted value in a similar stream.
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use futures::StreamExt;
    /// use std::ops::Deref;
    /// use async_symm_crypto::AsyncEncryption;
    ///
    /// let crypto = AsyncEncryption::new(
    ///     openssl::symm::Cipher::des_ede3_cbc(),
    ///     TEST_KEY,
    ///     Some(b"bcff0511"),
    /// );
    ///
    /// let mut enc_stream = crypto.encrypt_stream(get_text_byte_stream());
    ///
    /// let mut enc_bytes = Vec::new();
    ///
    /// while let Some(Ok(part)) = enc_stream.next().await {
    ///     enc_bytes.extend_from_slice(part.deref());
    /// }
    /// ```
    ///
    pub fn encrypt_stream(
        &'a self,
        stream: impl Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a,
    ) -> AsyncStreamEncryptTask<'a> {
        AsyncStreamEncryptTask::new(stream, self.cypher, self.key, self.iv)
    }

    /// Decrypt a Fallible Stream returning the encrypted value in a similar stream.
    ///
    /// The map will be created without any capacity. This function will not
    /// allocate.
    ///
    /// # Examples
    ///
    /// ```
    /// use futures::StreamExt;
    /// use std::ops::Deref;
    /// use async_symm_crypto::AsyncEncryption;
    ///
    /// let crypto = AsyncEncryption::new(
    ///     openssl::symm::Cipher::des_ede3_cbc(),
    ///     TEST_KEY,
    ///     Some(b"bcff0511"),
    /// );
    ///
    /// let enc_bytes_stream = get_encrypted_byte_stream(&encrypted_bytes);
    /// let mut dec_stream = crypto.decrypt_stream(enc_bytes_stream);
    /// let mut dec_bytes = Vec::new();
    /// while let Some(Ok(part)) = dec_stream.next().await {
    ///    dec_bytes.extend_from_slice(part.deref());
    /// }
    /// ```
    ///
    pub fn decrypt_stream(
        &'a self,
        stream: impl Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a,
    ) -> AsyncStreamDecryptTask<'a> {
        AsyncStreamDecryptTask::new(stream, self.cypher, self.key, self.iv)
    }
}

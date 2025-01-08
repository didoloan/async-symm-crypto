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

pub struct AsyncEncryption<'a> {
    cypher: openssl::symm::Cipher,
    key: &'a [u8],
    iv: Option<&'a [u8]>,
}

impl<'a> AsyncEncryption<'a> {
    pub fn new(cypher: openssl::symm::Cipher, key: &'a [u8], iv: Option<&'a [u8]>) -> Self {
        Self { cypher, key, iv }
    }

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
        // AsyncEncryptTask::new(bytes_to_encrypt, self.cypher, self.key, self.iv).await
    }

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
        // AsyncDecryptTask::new(bytes_to_decrypt, self.cypher, self.key, self.iv).await
    }

    pub fn encrypt_stream(
        &'a self,
        stream: impl Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a,
    ) -> AsyncStreamEncryptTask<'a> {
        AsyncStreamEncryptTask::new(stream, self.cypher, self.key, self.iv)
    }

    pub fn decrypt_stream(
        &'a self,
        stream: impl Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a,
    ) -> AsyncStreamDecryptTask<'a> {
        AsyncStreamDecryptTask::new(stream, self.cypher, self.key, self.iv)
    }
}

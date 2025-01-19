mod stream_cypher_op;
mod async_stream_dec_task;
mod async_stream_enc_task;
use std::{ops::Deref, pin::Pin};
use async_stream_dec_task::AsyncStreamDecryptTask;
use async_stream_enc_task::AsyncStreamEncryptTask;
use bytes::Bytes;
use futures::{Stream, StreamExt};

pub type StreamRef<'a> = Pin<&'a mut (dyn Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>>+ Unpin)>;

pub mod re_exports {
    pub use bytes;
    pub use futures;
    pub use openssl;
}

pub mod prelude {
    pub use crate::AsyncEncryption;
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
    /// use openssl;
    /// use async_symm_crypto::AsyncEncryption;
    /// 
    /// static TEST_STRING:&'static str = "Cryptographic protocols like TLS, SSH, IPsec, and OpenVPN commonly use block cipher algorithms, such as AES, Triple-DES, and Blowfish, to encrypt data between clients and servers. To use such algorithms, the data is broken into fixed-length chunks, called blocks, and each block is encrypted separately according to a mode of operation. Older block ciphers, such as Triple-DES and Blowfish use a block size of 64 bits, whereas AES uses a block size of 128 bits.";
    /// static TEST_KEY: &[u8; 24] = b"266126f0ebb836dbcff05110";
    /// 
    /// static ENCRYPTED_BASE64: &'static str = "4OLRDw2hg3CyK7II2I6Y2zEHH7LDqw/gQb8kOXEAqT9ULt0Ks66atiVnMgx5yWntPVq8hYREfDMXl0RRac5t8i7ro6zZY46OGUHyC2OvBPnbZPwAfX3hCKiT8BbEhp88XUBB/k2AEiefw9c25MaTp1S121vNub2N5tdOj6dd4SEpz7iB8Hm6V2MdUECVUZ/6a8HMRCLOtD9JSXFSce8/bucO3Ip+rFUP6bKaDzZ5peIRe+MiuHUqt6w1lXS0S8wRov9N8QkQq9/AIcY6qhwpFO7puqYCt7x3mRL1Q9sfS5su3q/NiBLmB8u+4UwnngfBiupjwmkq072iZItefHMpjBRMlzkCw1N0/32XnIi0jFKGVE9SBOMReFxtX0xsh5iRfg/xxtOJui6kV/xe015tjAMonYklWL9xwaueBXJZhcf9xZssmJzx5MR25p6eIoeiO1TQhy3oJiH3/OC3xD7+1ZZJepN8hKx+bTwdZzUxZ/cRjlShrEF0pojauFgunrNNmjdUbaNXa4Uk/LhdHrxci4RH8BKjiuJ0pWULdHh6xDV8cMMS30INDFT0JG4OqZCRFKBtOlSw8VxqQd/mBRSBlZZ6VdsVS2tpyGHurimGvac=";
    /// 
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let crypto = AsyncEncryption::new(
    ///         openssl::symm::Cipher::des_ede3_cbc(),
    ///         TEST_KEY, //size varies by cypher
    ///         Some(b"bcff0511"),
    ///     );
    ///     let enc_bytes:Vec<u8> = crypto.encrypt(TEST_STRING.as_bytes()).await.unwrap();
    ///     assert_eq!(ENCRYPTED_BASE64, &openssl::base64::encode_block(&enc_bytes));
    ///     Ok(())
    /// }
    /// ```
    ///
    pub async fn encrypt(
        &self,
        bytes_to_encrypt: &'a [u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes_stream = futures::stream::iter(
            bytes_to_encrypt
                .chunks(self.cypher.block_size() * 2)
                .map(Bytes::copy_from_slice)
                .map(Ok),
        );

        let mut stream = self.encrypt_stream(&mut bytes_stream)?;

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
    /// use openssl;
    /// use tokio; 
    ///
    /// static TEST_STRING:&'static str = "Cryptographic protocols like TLS, SSH, IPsec, and OpenVPN commonly use block cipher algorithms, such as AES, Triple-DES, and Blowfish, to encrypt data between clients and servers. To use such algorithms, the data is broken into fixed-length chunks, called blocks, and each block is encrypted separately according to a mode of operation. Older block ciphers, such as Triple-DES and Blowfish use a block size of 64 bits, whereas AES uses a block size of 128 bits.";
    /// static TEST_KEY: &[u8; 24] = b"266126f0ebb836dbcff05110";
    /// 
    /// static ENCRYPTED_BASE64: &'static str = "4OLRDw2hg3CyK7II2I6Y2zEHH7LDqw/gQb8kOXEAqT9ULt0Ks66atiVnMgx5yWntPVq8hYREfDMXl0RRac5t8i7ro6zZY46OGUHyC2OvBPnbZPwAfX3hCKiT8BbEhp88XUBB/k2AEiefw9c25MaTp1S121vNub2N5tdOj6dd4SEpz7iB8Hm6V2MdUECVUZ/6a8HMRCLOtD9JSXFSce8/bucO3Ip+rFUP6bKaDzZ5peIRe+MiuHUqt6w1lXS0S8wRov9N8QkQq9/AIcY6qhwpFO7puqYCt7x3mRL1Q9sfS5su3q/NiBLmB8u+4UwnngfBiupjwmkq072iZItefHMpjBRMlzkCw1N0/32XnIi0jFKGVE9SBOMReFxtX0xsh5iRfg/xxtOJui6kV/xe015tjAMonYklWL9xwaueBXJZhcf9xZssmJzx5MR25p6eIoeiO1TQhy3oJiH3/OC3xD7+1ZZJepN8hKx+bTwdZzUxZ/cRjlShrEF0pojauFgunrNNmjdUbaNXa4Uk/LhdHrxci4RH8BKjiuJ0pWULdHh6xDV8cMMS30INDFT0JG4OqZCRFKBtOlSw8VxqQd/mBRSBlZZ6VdsVS2tpyGHurimGvac=";
    ///
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let crypto = AsyncEncryption::new(
    ///         openssl::symm::Cipher::des_ede3_cbc(),
    ///         TEST_KEY,
    ///         Some(b"bcff0511"),
    ///     );
    ///     let plain_bytes = crypto
    ///     .decrypt(&openssl::base64::decode_block(ENCRYPTED_BASE64).unwrap())
    ///     .await?;
    /// 
    ///     assert_eq!(
    ///         TEST_STRING,
    ///         String::from_utf8(plain_bytes).unwrap().as_str()
    ///     );
    ///     Ok(())
    /// }
    ///
    /// ```
    ///
    pub async fn decrypt(
        &self,
        bytes_to_decrypt: &'a [u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes_stream = futures::stream::iter(
            bytes_to_decrypt
                .chunks(self.cypher.block_size() * 2)
                .map(Bytes::copy_from_slice)
                .map(Ok),
        );

        let mut stream = self.decrypt_stream(&mut bytes_stream)?;

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
    /// use async_symm_crypto::AsyncEncryption;
    /// use openssl;
    /// use futures::StreamExt;
    /// use std::ops::Deref;
    /// use std::pin::Pin;
    /// use tokio; 
    ///
    /// static TEST_STRING:&'static str = "Cryptographic protocols like TLS, SSH, IPsec, and OpenVPN commonly use block cipher algorithms, such as AES, Triple-DES, and Blowfish, to encrypt data between clients and servers. To use such algorithms, the data is broken into fixed-length chunks, called blocks, and each block is encrypted separately according to a mode of operation. Older block ciphers, such as Triple-DES and Blowfish use a block size of 64 bits, whereas AES uses a block size of 128 bits.";
    /// static TEST_KEY: &[u8; 24] = b"266126f0ebb836dbcff05110";
    /// 
    /// static ENCRYPTED_BASE64: &'static str = "4OLRDw2hg3CyK7II2I6Y2zEHH7LDqw/gQb8kOXEAqT9ULt0Ks66atiVnMgx5yWntPVq8hYREfDMXl0RRac5t8i7ro6zZY46OGUHyC2OvBPnbZPwAfX3hCKiT8BbEhp88XUBB/k2AEiefw9c25MaTp1S121vNub2N5tdOj6dd4SEpz7iB8Hm6V2MdUECVUZ/6a8HMRCLOtD9JSXFSce8/bucO3Ip+rFUP6bKaDzZ5peIRe+MiuHUqt6w1lXS0S8wRov9N8QkQq9/AIcY6qhwpFO7puqYCt7x3mRL1Q9sfS5su3q/NiBLmB8u+4UwnngfBiupjwmkq072iZItefHMpjBRMlzkCw1N0/32XnIi0jFKGVE9SBOMReFxtX0xsh5iRfg/xxtOJui6kV/xe015tjAMonYklWL9xwaueBXJZhcf9xZssmJzx5MR25p6eIoeiO1TQhy3oJiH3/OC3xD7+1ZZJepN8hKx+bTwdZzUxZ/cRjlShrEF0pojauFgunrNNmjdUbaNXa4Uk/LhdHrxci4RH8BKjiuJ0pWULdHh6xDV8cMMS30INDFT0JG4OqZCRFKBtOlSw8VxqQd/mBRSBlZZ6VdsVS2tpyGHurimGvac=";
    ///
    /// fn get_text_byte_stream(
    /// ) -> impl futures::Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send {
    ///     futures::stream::iter(
    ///         TEST_STRING
    ///         .as_bytes()
    ///         .chunks(16)
    ///         .map(bytes::Bytes::copy_from_slice)
    ///         .map(|x| Ok(x)),
    ///     )
    /// }
    /// 
    /// 
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let crypto = AsyncEncryption::new(
    ///         openssl::symm::Cipher::des_ede3_cbc(),
    ///         TEST_KEY,
    ///         Some(b"bcff0511"),
    ///     );
    /// 
    ///     let mut bytes_stream = get_text_byte_stream();
    ///
    ///     let mut enc_stream = crypto.encrypt_stream(&mut bytes_stream)?;
    ///
    ///     let mut enc_bytes = Vec::new();
    ///
    ///     while let Some(Ok(part)) = enc_stream.next().await {
    ///         enc_bytes.extend_from_slice(part.deref());
    ///     }
    /// 
    ///     assert_eq!(ENCRYPTED_BASE64, &openssl::base64::encode_block(&enc_bytes));
    ///     Ok(())
    /// }
    /// ```
    ///
    pub fn encrypt_stream(
        &'a self,
        stream: &'a mut (dyn Stream<Item = Result<Bytes, Box<dyn std::error::Error>>> + Unpin),
        // stream: StreamRef<'a>
    ) -> Result<AsyncStreamEncryptTask<'a>, Box<dyn std::error::Error>> {
        AsyncStreamEncryptTask::new(Pin::new(stream), self.cypher, self.key, self.iv)
    }

    /// Decrypt a Fallible Stream returning the encrypted value in a similar stream.
    ///
    /// The map will be created without any capacity. This function will not
    /// allocate.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_symm_crypto::AsyncEncryption;
    /// use openssl;
    /// use tokio;
    /// use futures::StreamExt;
    /// use std::ops::Deref;
    /// use std::pin::Pin;
    ///
    /// static TEST_STRING:&'static str = "Cryptographic protocols like TLS, SSH, IPsec, and OpenVPN commonly use block cipher algorithms, such as AES, Triple-DES, and Blowfish, to encrypt data between clients and servers. To use such algorithms, the data is broken into fixed-length chunks, called blocks, and each block is encrypted separately according to a mode of operation. Older block ciphers, such as Triple-DES and Blowfish use a block size of 64 bits, whereas AES uses a block size of 128 bits.";
    /// static TEST_KEY: &[u8; 24] = b"266126f0ebb836dbcff05110";
    /// 
    /// static ENCRYPTED_BASE64: &'static str = "4OLRDw2hg3CyK7II2I6Y2zEHH7LDqw/gQb8kOXEAqT9ULt0Ks66atiVnMgx5yWntPVq8hYREfDMXl0RRac5t8i7ro6zZY46OGUHyC2OvBPnbZPwAfX3hCKiT8BbEhp88XUBB/k2AEiefw9c25MaTp1S121vNub2N5tdOj6dd4SEpz7iB8Hm6V2MdUECVUZ/6a8HMRCLOtD9JSXFSce8/bucO3Ip+rFUP6bKaDzZ5peIRe+MiuHUqt6w1lXS0S8wRov9N8QkQq9/AIcY6qhwpFO7puqYCt7x3mRL1Q9sfS5su3q/NiBLmB8u+4UwnngfBiupjwmkq072iZItefHMpjBRMlzkCw1N0/32XnIi0jFKGVE9SBOMReFxtX0xsh5iRfg/xxtOJui6kV/xe015tjAMonYklWL9xwaueBXJZhcf9xZssmJzx5MR25p6eIoeiO1TQhy3oJiH3/OC3xD7+1ZZJepN8hKx+bTwdZzUxZ/cRjlShrEF0pojauFgunrNNmjdUbaNXa4Uk/LhdHrxci4RH8BKjiuJ0pWULdHh6xDV8cMMS30INDFT0JG4OqZCRFKBtOlSw8VxqQd/mBRSBlZZ6VdsVS2tpyGHurimGvac=";
    ///
    /// fn get_encrypted_byte_stream<'a>(
    ///     enc_bytes: &'a [u8],
    /// ) -> impl futures::Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a {
    ///     futures::stream::iter(
    ///         enc_bytes
    ///        .chunks(16)
    ///        .map(bytes::Bytes::copy_from_slice)
    ///        .map(|x| Ok(x)),
    ///     )
    /// }
    /// 
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     
    ///     let crypto = AsyncEncryption::new(
    ///         openssl::symm::Cipher::des_ede3_cbc(),
    ///         TEST_KEY,
    ///         Some(b"bcff0511"),
    ///     );
    /// 
    ///     let encrypted_bytes = openssl::base64::decode_block(ENCRYPTED_BASE64).unwrap();
    ///     let mut enc_bytes_stream = get_encrypted_byte_stream(&encrypted_bytes);
    ///     let mut dec_stream = crypto.decrypt_stream(&mut enc_bytes_stream)?;
    ///     let mut dec_bytes = Vec::new();
    ///     while let Some(Ok(part)) = dec_stream.next().await {
    ///         dec_bytes.extend_from_slice(part.deref());
    ///     }
    /// 
    ///     assert_eq!(TEST_STRING, String::from_utf8(dec_bytes).unwrap());
    ///     Ok(())
    /// }
    /// ```
    ///
    pub fn decrypt_stream(
        &'a self,
        stream: &'a mut (dyn Stream<Item = Result<Bytes, Box<dyn std::error::Error>>> + Unpin),
    ) -> Result<AsyncStreamDecryptTask<'a>, Box<dyn std::error::Error>> {
        AsyncStreamDecryptTask::new(Pin::new(stream), self.cypher, self.key, self.iv)
    }
}

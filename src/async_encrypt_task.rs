use openssl::symm::Crypter;
use std::{future::Future, task::Poll};

pub(crate) struct AsyncEncryptTask<'a> {
    backing: &'a [u8],
    buffer: Vec<u8>,
    cur_index: usize,
    bytes_pushed: usize,
    blk_size: usize,
    enc: Crypter,
}

impl<'a> AsyncEncryptTask<'a> {
    pub(crate) fn new(
        input_bytes: &'a [u8],
        cipher: openssl::symm::Cipher,
        key: &'a [u8],
        iv: Option<&'a [u8]>,
    ) -> AsyncEncryptTask<'a> {
        AsyncEncryptTask {
            backing: input_bytes,
            buffer: Vec::with_capacity(input_bytes.len() + cipher.block_size()),
            cur_index: 0,
            bytes_pushed: 0,
            blk_size: cipher.block_size(),
            enc: openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, iv)
                .unwrap(),
        }
    }
}

impl Future for AsyncEncryptTask<'_> {
    type Output = Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut temp_buf = vec![0; self.blk_size * 2];

        let slice = if self.cur_index + self.blk_size > self.backing.len() {
            &self.backing[self.cur_index..]
        } else {
            &self.backing[self.cur_index..self.cur_index + self.blk_size]
        };

        let count = match self.enc.update(slice, &mut temp_buf) {
            Ok(count) => {
                self.buffer.extend_from_slice(&temp_buf[..count]);
                count
            }
            Err(err) => {
                return Poll::Ready(Err(Err(err)?));
            }
        };

        if self.cur_index != self.backing.len() {
            self.cur_index += slice.len();
            self.bytes_pushed += count;

            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let bytes_sofar = self.bytes_pushed + count;
        let mut last_buffer = vec![0u8; self.blk_size * 2];

        match self.enc.finalize(&mut last_buffer) {
            Ok(last_bytes_size) => {
                self.buffer
                    .extend_from_slice(&last_buffer[..last_bytes_size]);
                self.buffer.truncate(bytes_sofar + last_bytes_size);
                Poll::Ready(Ok(core::mem::take(&mut self.buffer)))
            }
            Err(err) => {
                return Poll::Ready(Err(Err(err)?));
            }
        }
    }
}

use futures::{stream::BoxStream, Stream, StreamExt};
use openssl::symm::Crypter;
use std::task::Poll;

pub struct AsyncStreamDecryptTask<'a> {
    stream_ref: BoxStream<'a, Result<bytes::Bytes, Box<dyn std::error::Error>>>,
    buffer: Vec<u8>,
    cur_index: usize,
    bytes_pushed: usize,
    blk_size: usize,
    dec: Crypter,
    eos: bool,
}

impl<'a> AsyncStreamDecryptTask<'a> {
    pub(crate) fn new(
        stream_ref: impl Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a,
        cipher: openssl::symm::Cipher,
        key: &'a [u8],
        iv: Option<&'a [u8]>,
    ) -> Self {
        Self {
            stream_ref: stream_ref.boxed(),
            buffer: Vec::with_capacity(128),
            cur_index: 0,
            bytes_pushed: 0,
            blk_size: cipher.block_size(),
            dec: openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Decrypt, key, iv)
                .unwrap(),
            eos: false,
        }
    }
}

impl futures::Stream for AsyncStreamDecryptTask<'_> {
    type Item = Result<bytes::Bytes, Box<dyn std::error::Error>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.stream_ref.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(piece))) => {
                let mut temp_buf = vec![0; piece.len() + self.blk_size];

                let count = match self.dec.update(piece.to_vec().as_slice(), &mut temp_buf) {
                    Ok(count) => count,
                    Err(err) => {
                        return Poll::Ready(Some(Err(Err(err)?)));
                    }
                };

                self.bytes_pushed += count;
                self.cur_index += piece.len();
                // cx.waker().wake_by_ref();
                Poll::Ready(Some(Ok(bytes::Bytes::copy_from_slice(&temp_buf[..count]))))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => {
                if self.eos {
                    return Poll::Ready(None);
                }
                let bytes_sofar = self.bytes_pushed;
                let mut last_buffer = vec![0; self.blk_size * 2];
                match self.dec.finalize(&mut last_buffer) {
                    Ok(last_bytes_size) => {
                        self.buffer
                            .extend_from_slice(&last_buffer[..last_bytes_size]);
                        self.buffer.truncate(bytes_sofar + last_bytes_size);
                        self.eos = true;
                        Poll::Ready(Some(Ok(bytes::Bytes::copy_from_slice(
                            &last_buffer[..last_bytes_size],
                        ))))
                    }
                    Err(err) => {
                        return Poll::Ready(Some(Err(Err(err)?)));
                    }
                }
            }
            Poll::Pending => {
                // cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

// impl std::future::Future for AsyncStreamDecryptTask<'_> {
//     type Output = Result<Vec<u8>, Box<dyn std::error::Error>>;

//     fn poll(
//         mut self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Self::Output> {
//         match self.stream_ref.poll_next_unpin(cx) {
//             Poll::Ready(Some(Ok(piece))) => {
//                 let mut temp_buf = vec![0; piece.len() + self.blk_size];

//                 let count = match self.dec.update(piece.to_vec().as_slice(), &mut temp_buf) {
//                     Ok(count) => {
//                         self.buffer.extend_from_slice(&temp_buf[..count]);
//                         count
//                     }
//                     Err(err) => {
//                         return Poll::Ready(Err(Err(err)?));
//                     }
//                 };

//                 self.bytes_pushed += count;
//                 self.cur_index += piece.len();
//                 cx.waker().wake_by_ref();
//                 Poll::Pending
//             }
//             Poll::Ready(Some(Err(err))) => {
//                 Poll::Ready(Err(err))
//             }
//             Poll::Ready(None) => {
//                 let bytes_sofar = self.bytes_pushed;
//                 let mut last_buffer = vec![0; self.blk_size * 2];
//                 match self.dec.finalize(&mut last_buffer) {
//                     Ok(last_bytes_size) => {
//                         self.buffer
//                             .extend_from_slice(&last_buffer[..last_bytes_size]);
//                         self.buffer.truncate(bytes_sofar + last_bytes_size);
//                         Poll::Ready(Ok(core::mem::take(&mut self.buffer)))
//                     }
//                     Err(err) => {
//                         return Poll::Ready(Err(Err(err)?));
//                     }
//                 }
//             }
//             Poll::Pending => {
//                 cx.waker().wake_by_ref();
//                 Poll::Pending
//             }
//         }
//     }
// }

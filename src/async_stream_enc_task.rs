use futures::{stream::BoxStream, Stream, StreamExt};
use openssl::symm::Crypter;
use std::task::Poll;

pub struct AsyncStreamEncryptTask<'a> {
    stream_ref: BoxStream<'a, Result<bytes::Bytes, Box<dyn std::error::Error>>>,
    blk_size: usize,
    enc: Crypter,
    eos: bool
}

impl<'a> AsyncStreamEncryptTask<'a> {
    pub(crate) fn new(
        stream_ref: impl Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error>>> + Send + 'a,
        cipher: openssl::symm::Cipher,
        key: &'a [u8],
        iv: Option<&'a [u8]>,
    ) -> Self {
        Self {
            stream_ref: stream_ref.boxed(),
            blk_size: cipher.block_size(),
            enc: openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, iv)
                .unwrap(),
            eos: false,
        }
    }
}

impl futures::Stream for AsyncStreamEncryptTask<'_> {
    type Item = Result<bytes::Bytes, Box<dyn std::error::Error>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.stream_ref.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(piece))) => {
                let mut temp_buf = vec![0; piece.len() + self.blk_size];

                let count = match self.enc.update(piece.to_vec().as_slice(), &mut temp_buf) {
                    Ok(count) => count,
                    Err(err) => {
                        return Poll::Ready(Some(Err(Err(err)?)));
                    }
                };

                Poll::Ready(Some(Ok(bytes::Bytes::copy_from_slice(&temp_buf[..count]))))
            },
            Poll::Ready(None) => {
                if self.eos {
                    return Poll::Ready(None);
                }
                let mut last_buffer = vec![0; self.blk_size * 2];
                match self.enc.finalize(&mut last_buffer) {
                    Ok(last_bytes_size) => {
                        self.eos = true;
                        Poll::Ready(Some(Ok(bytes::Bytes::copy_from_slice(
                            &last_buffer[..last_bytes_size],
                        ))))
                    }
                    Err(err) => {
                        return Poll::Ready(Some(Err(Err(err)?)));
                    }
                }
            },
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Pending => {
                Poll::Pending
            }
        }
    }
}

// impl std::future::Future for AsyncStreamEncryptTask<'_> {
//     type Output = Result<Vec<u8>, Box<dyn std::error::Error>>;

//     fn poll(
//         mut self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Self::Output> {
//         match self.stream_ref.poll_next_unpin(cx) {
//             Poll::Ready(Some(Ok(piece))) => {
//                 let mut temp_buf = vec![0; piece.len() + self.blk_size];

//                 let count = match self.enc.update(piece.to_vec().as_slice(), &mut temp_buf) {
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
//                 match self.enc.finalize(&mut last_buffer) {
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

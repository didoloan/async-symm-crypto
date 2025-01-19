use bytes::BytesMut;
use futures::StreamExt;
use openssl::symm::Crypter;
use std::{cell::RefCell, task::Poll};

use crate::{stream_cypher_op::STREAM_CYPHER_POLL_OPTION as stream_cypher_poll_option, StreamRef};

pub struct AsyncStreamDecryptTask<'a> {
    stream_ref: StreamRef<'a>,
    blk_size: usize,
    buf: RefCell<BytesMut>,
    dec: RefCell<Crypter>,
    eos: bool,
}



impl<'a> AsyncStreamDecryptTask<'a> {
    pub(crate) fn new(
        stream_ref: StreamRef<'a>,
        cipher: openssl::symm::Cipher,
        key: &'a [u8],
        iv: Option<&'a [u8]>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            stream_ref,
            blk_size: cipher.block_size(),
            buf: RefCell::new(BytesMut::new()),
            dec: RefCell::new(openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Decrypt, key, iv)?),
            eos: false,
        })
    }
}

impl<'a> futures::Stream for AsyncStreamDecryptTask<'a> {
    type Item = Result<bytes::Bytes, Box<dyn std::error::Error>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let (poll_res, eos) = stream_cypher_poll_option(self.stream_ref.poll_next_unpin(cx), &self.buf, &self.dec, self.blk_size, &self.eos);
        if eos {
            self.eos = true;
        }
        poll_res        
    }
}

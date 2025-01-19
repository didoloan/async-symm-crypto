use bytes::BytesMut;
use openssl::symm::Crypter;
use std::{
    cell::RefCell,
    task::Poll
};

pub const STREAM_CYPHER_POLL_OPTION:for<'a> fn(
    Poll<Option<Result<bytes::Bytes, Box<dyn std::error::Error>>>>,
    &'a RefCell<BytesMut>,
    &'a RefCell<Crypter>,
    usize,
    &'a bool,
) -> (Poll<Option<Result<bytes::Bytes, Box<dyn std::error::Error>>>>, bool) = |
    stream_poll,
    buf,
    enc_dec,
    blk_size,
    eos
| {
    buf.borrow_mut().fill(0);
    match stream_poll {
        Poll::Ready(Some(Ok(piece))) => {
            if buf.borrow().len() < piece.len() + blk_size {
                buf.borrow_mut().resize(blk_size + piece.len(), 0);
            }

            let count = match enc_dec
                .borrow_mut()
                .update(piece.as_ref(), &mut buf.borrow_mut())
            {
                Ok(count) => count,
                Err(err) => {
                    return (Poll::Ready(Some(Err(Box::new(err)))), false);
                }
            };

            buf.borrow_mut().truncate(count);
            (Poll::Ready(Some(Ok(buf.borrow().to_owned().freeze()))), false)
        }
        Poll::Ready(None) => {
            if *eos {
                return (Poll::Ready(None), *eos);
            }
            buf.borrow_mut().fill(0);
            let last_bytes_size = match enc_dec.borrow_mut().finalize(&mut buf.borrow_mut()) {
                Ok(last_bytes_size) => last_bytes_size,
                Err(err) => {
                    return (Poll::Ready(Some(Err(Box::new(err)))), true);
                }
            };
            
            buf.borrow_mut().truncate(last_bytes_size);
            (Poll::Ready(Some(Ok(buf.borrow().to_owned().freeze()))), true)
        },
        Poll::Ready(Some(Err(err))) => (Poll::Ready(Some(Err(err))), false),
        Poll::Pending => (Poll::Pending, false)
    }
};


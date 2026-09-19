use std::convert::Infallible;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

const RESPONSE_BODY_CHANNEL_CAPACITY: usize = 4;

pub(super) fn split_extended_connect_body(
    request_body: Incoming,
) -> (
    ExtendedConnectReader,
    ExtendedConnectWriter,
    ExtendedConnectResponseBody,
) {
    let (sender, receiver) = mpsc::channel(RESPONSE_BODY_CHANNEL_CAPACITY);
    (
        ExtendedConnectReader::new(request_body),
        ExtendedConnectWriter::new(sender),
        ExtendedConnectResponseBody { receiver },
    )
}

pub(super) struct ExtendedConnectReader {
    body: Incoming,
    buffered: Bytes,
}

impl ExtendedConnectReader {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            buffered: Bytes::new(),
        }
    }
}

impl AsyncRead for ExtendedConnectReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.buffered.has_remaining() {
                let copy_len = destination.remaining().min(self.buffered.remaining());
                destination.put_slice(&self.buffered[..copy_len]);
                self.buffered.advance(copy_len);
                return Poll::Ready(Ok(()));
            }

            match ready!(Pin::new(&mut self.body).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        self.buffered = data.clone();
                    }
                    // HTTP/2 trailers do not carry WebSocket bytes. Ignore them and
                    // continue until DATA or end-of-stream is observed.
                }
                Some(Err(error)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, error)));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

pub(super) struct ExtendedConnectWriter {
    sender: PollSender<Bytes>,
}

impl ExtendedConnectWriter {
    fn new(sender: mpsc::Sender<Bytes>) -> Self {
        Self {
            sender: PollSender::new(sender),
        }
    }

    fn poll_send_bytes(&mut self, cx: &mut Context<'_>, bytes: Bytes) -> Poll<io::Result<usize>> {
        let len = bytes.len();
        ready!(self.sender.poll_reserve(cx)).map_err(channel_closed)?;
        self.sender.send_item(bytes).map_err(channel_closed)?;
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for ExtendedConnectWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.poll_send_bytes(cx, Bytes::copy_from_slice(buffer))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total_len = buffers.iter().map(|buffer| buffer.len()).sum::<usize>();
        if total_len == 0 {
            return Poll::Ready(Ok(0));
        }

        let mut bytes = BytesMut::with_capacity(total_len);
        for buffer in buffers {
            bytes.extend_from_slice(buffer);
        }
        self.poll_send_bytes(cx, bytes.freeze())
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sender.close();
        Poll::Ready(Ok(()))
    }
}

fn channel_closed<T>(_error: tokio_util::sync::PollSendError<T>) -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "HTTP/2 extended CONNECT response stream closed",
    )
}

pub(super) struct ExtendedConnectResponseBody {
    receiver: mpsc::Receiver<Bytes>,
}

impl Body for ExtendedConnectResponseBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

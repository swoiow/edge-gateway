use std::error::Error;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Body;

pub(crate) type BoxError = Box<dyn Error + Send + Sync>;
pub(crate) type ResponseBody = UnsyncBoxBody<Bytes, BoxError>;

pub(crate) fn boxed<B>(body: B) -> ResponseBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::body::{Frame, SizeHint};

use crate::gateway::admission::RequestLease;

pub(crate) fn with_admission(inner: ResponseBody, lease: Arc<RequestLease>) -> ResponseBody {
    boxed(AdmissionBody {
        inner: Box::pin(inner),
        lease: Some(lease),
    })
}
struct AdmissionBody {
    inner: Pin<Box<ResponseBody>>,
    lease: Option<Arc<RequestLease>>,
}
impl Body for AdmissionBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let result = self.inner.as_mut().poll_frame(cx);
        if matches!(&result, Poll::Ready(None) | Poll::Ready(Some(Err(_))))
            || self.inner.is_end_stream()
        {
            self.lease.take();
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

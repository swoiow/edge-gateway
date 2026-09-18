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

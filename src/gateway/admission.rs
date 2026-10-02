use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;

/// The transport permit survives HTTP/1 Upgrade via the request lease retained
/// by the relay. A completed HTTP connection driver must not release a live WS.
pub(crate) struct RequestLease {
    _request_permit: OwnedSemaphorePermit,
    _transport_permit: Arc<OwnedSemaphorePermit>,
}

impl RequestLease {
    pub(crate) fn new(
        request_permit: OwnedSemaphorePermit,
        transport_permit: Arc<OwnedSemaphorePermit>,
    ) -> Arc<Self> {
        Arc::new(Self {
            _request_permit: request_permit,
            _transport_permit: transport_permit,
        })
    }
}

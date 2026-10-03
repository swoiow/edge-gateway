//! Application message bound and fragment ordering on top of SDK frame parsing.
//! Control handling and masking remain in fastwebsockets. No payload interpretation.
use fastwebsockets::{Frame, OpCode, Payload, WebSocketError};

pub(super) struct MessageSequence {
    maximum: usize,
    opcode: Option<OpCode>,
    bytes: usize,
    utf8_tail: Vec<u8>,
}
impl MessageSequence {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            maximum,
            opcode: None,
            bytes: 0,
            utf8_tail: Vec::new(),
        }
    }
    pub(super) fn validate(&mut self, frame: &Frame<'_>) -> Result<(), WebSocketError> {
        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                if self.opcode.is_some() {
                    return Err(WebSocketError::InvalidFragment);
                }
                self.opcode = Some(frame.opcode);
                self.bytes = 0;
                self.utf8_tail.clear();
            }
            OpCode::Continuation => {
                if self.opcode.is_none() {
                    return Err(WebSocketError::InvalidContinuationFrame);
                }
            }
            OpCode::Close | OpCode::Ping | OpCode::Pong => {
                return if frame.payload.len() <= 125 {
                    Ok(())
                } else {
                    Err(WebSocketError::FrameTooLarge)
                };
            }
        }
        self.bytes = self
            .bytes
            .checked_add(frame.payload.len())
            .ok_or(WebSocketError::FrameTooLarge)?;
        if self.bytes > self.maximum {
            return Err(WebSocketError::FrameTooLarge);
        }
        if self.opcode == Some(OpCode::Text) {
            self.validate_utf8(&frame.payload, frame.fin)?;
        }
        if frame.fin {
            self.opcode = None;
            self.bytes = 0;
        }
        Ok(())
    }
    fn validate_utf8(
        &mut self,
        mut data: &[u8],
        final_fragment: bool,
    ) -> Result<(), WebSocketError> {
        // A validated incomplete suffix contains at most three bytes. Complete
        // its one codepoint before validating the remaining slice without copying.
        if let Some(first) = self.utf8_tail.first().copied() {
            let width = if first < 0xe0 {
                2
            } else if first < 0xf0 {
                3
            } else {
                4
            };
            let take = (width - self.utf8_tail.len()).min(data.len());
            self.utf8_tail.extend_from_slice(&data[..take]);
            data = &data[take..];
            match std::str::from_utf8(&self.utf8_tail) {
                Ok(_) => self.utf8_tail.clear(),
                Err(error) if error.error_len().is_none() && !final_fragment => return Ok(()),
                Err(_) => return Err(WebSocketError::InvalidUTF8),
            }
        }
        match std::str::from_utf8(data) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_none() && !final_fragment => {
                self.utf8_tail.extend_from_slice(&data[error.valid_up_to()..]);
                Ok(())
            }
            Err(_) => Err(WebSocketError::InvalidUTF8),
        }
    }
}

pub(super) struct BoundedMessages {
    sequence: MessageSequence,
    fragments: Option<(OpCode, Vec<u8>)>,
}
impl BoundedMessages {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            sequence: MessageSequence::new(maximum),
            fragments: None,
        }
    }
    pub(super) fn collect(
        &mut self,
        frame: Frame<'_>,
    ) -> Result<Option<Frame<'static>>, WebSocketError> {
        self.sequence.validate(&frame)?;
        match frame.opcode {
            OpCode::Text | OpCode::Binary if !frame.fin => {
                self.fragments = Some((frame.opcode, frame.payload.into()));
                Ok(None)
            }
            OpCode::Continuation => {
                let (opcode, buffer) =
                    self.fragments.as_mut().ok_or(WebSocketError::InvalidContinuationFrame)?;
                let length = buffer
                    .len()
                    .checked_add(frame.payload.len())
                    .ok_or(WebSocketError::FrameTooLarge)?;
                if length > self.sequence.maximum {
                    return Err(WebSocketError::FrameTooLarge);
                }
                if length > buffer.capacity() {
                    let capacity =
                        length.max(buffer.capacity().saturating_mul(2)).min(self.sequence.maximum);
                    buffer.reserve_exact(capacity - buffer.len());
                }
                buffer.extend_from_slice(&frame.payload);
                let opcode = *opcode;
                if frame.fin {
                    let (_, payload) =
                        self.fragments.take().ok_or(WebSocketError::InvalidContinuationFrame)?;
                    Ok(Some(Frame::new(true, opcode, None, payload.into())))
                } else {
                    Ok(None)
                }
            }
            _ => {
                // SDK reads normally yield Bytes; retain that allocation rather
                // than introducing a copy on each unfragmented message.
                let payload = match frame.payload {
                    Payload::Owned(data) => Payload::Owned(data),
                    Payload::Bytes(data) => Payload::Bytes(data),
                    Payload::Borrowed(data) => Payload::Owned(data.to_vec()),
                    Payload::BorrowedMut(data) => Payload::Owned(data.to_vec()),
                };
                Ok(Some(Frame::new(frame.fin, frame.opcode, None, payload)))
            }
        }
    }
}

use std::io::{Read, Result};

pub(crate) struct SplitVolumeState<P> {
    pending: Option<P>,
}

impl<P> SplitVolumeState<P> {
    pub(crate) fn new() -> Self {
        Self { pending: None }
    }

    pub(crate) fn advance(
        &mut self,
        split_before: bool,
        split_after: bool,
    ) -> SplitVolumeStep<'_, P> {
        match (self.pending.is_some(), split_before, split_after) {
            (false, false, false) => SplitVolumeStep::Regular,
            (false, false, true) => SplitVolumeStep::Start,
            // The match arm's first field proves a pending split exists.
            (true, true, true) => {
                SplitVolumeStep::Continue(self.pending.as_mut().expect("pending split"))
            }
            // The match arm's first field proves a pending split exists.
            (true, true, false) => {
                SplitVolumeStep::Finish(self.pending.take().expect("pending split"))
            }
            // Error states leave pending untouched; callers currently return
            // the error immediately rather than attempting recovery.
            (false, true, _) => SplitVolumeStep::MissingFirst,
            (true, false, _) => SplitVolumeStep::Interrupted,
        }
    }

    pub(crate) fn begin(&mut self, pending: P) {
        debug_assert!(self.pending.is_none());
        self.pending = Some(pending);
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

pub(crate) enum SplitVolumeStep<'a, P> {
    Regular,
    Start,
    Continue(&'a mut P),
    Finish(P),
    MissingFirst,
    Interrupted,
}

/// One fragment of a split member, opened only when the chain reaches it.
/// Failure surfaces as an `io::Error` on the read that needed it - the
/// fragment is opened from inside `Read::read`, which has no other channel.
pub(crate) type FragmentOpener<'a> =
    Box<dyn FnOnce() -> Result<Box<dyn Read + Send + 'a>> + Send + 'a>;

/// A fragment chain that holds openers rather than open readers.
///
/// A path-backed range reader is a live `File`, and the legacy formats built
/// one for EVERY fragment before reading a byte: a ~300-volume split member
/// (an ordinary shape for a large RAR4 release) wanted 300 descriptors at
/// once and died on `EMFILE` under the common 256 soft limit before
/// extraction even started. RAR5 has always opened fragments lazily; this is
/// the same discipline for RAR 1.3 and 1.5-4, and it keeps descriptor use
/// O(1) - the finished fragment is dropped as soon as the next one opens.
pub(crate) struct LazyChainedReader<'a> {
    openers: Vec<Option<FragmentOpener<'a>>>,
    index: usize,
    current: Option<Box<dyn Read + Send + 'a>>,
}

impl<'a> LazyChainedReader<'a> {
    pub(crate) fn new(openers: Vec<FragmentOpener<'a>>) -> Self {
        Self {
            openers: openers.into_iter().map(Some).collect(),
            index: 0,
            current: None,
        }
    }
}

impl Read for LazyChainedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        loop {
            if self.current.is_none() {
                let Some(slot) = self.openers.get_mut(self.index) else {
                    return Ok(0);
                };
                let opener = slot
                    .take()
                    .expect("a fragment opener is taken exactly once");
                self.current = Some(opener()?);
            }
            let read = self
                .current
                .as_mut()
                .expect("just opened")
                .read(out)?;
            if read != 0 {
                return Ok(read);
            }
            // Drop the fragment BEFORE opening the next one - that is the
            // whole point of the lazy chain.
            self.current = None;
            self.index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn split_volume_state_reports_regular_member_without_pending_split() {
        let mut state = SplitVolumeState::<u8>::new();

        assert!(matches!(
            state.advance(false, false),
            SplitVolumeStep::Regular
        ));
        assert!(!state.is_pending());
    }

    #[test]
    fn split_volume_state_tracks_start_continue_and_finish() {
        let mut state = SplitVolumeState::new();

        assert!(matches!(state.advance(false, true), SplitVolumeStep::Start));
        state.begin(vec![1]);
        assert!(state.is_pending());

        match state.advance(true, true) {
            SplitVolumeStep::Continue(parts) => parts.push(2),
            _ => panic!("expected split continuation"),
        }
        assert!(state.is_pending());

        match state.advance(true, false) {
            SplitVolumeStep::Finish(parts) => assert_eq!(parts, vec![1, 2]),
            _ => panic!("expected split finish"),
        }
        assert!(!state.is_pending());
    }

    #[test]
    fn split_volume_state_reports_orphan_continuation() {
        let mut state = SplitVolumeState::<u8>::new();

        assert!(matches!(
            state.advance(true, false),
            SplitVolumeStep::MissingFirst
        ));
        assert!(matches!(
            state.advance(true, true),
            SplitVolumeStep::MissingFirst
        ));
        assert!(!state.is_pending());
    }

    #[test]
    fn split_volume_state_reports_regular_entry_interrupting_pending_split() {
        let mut state = SplitVolumeState::new();
        assert!(matches!(state.advance(false, true), SplitVolumeStep::Start));
        state.begin(7u8);

        assert!(matches!(
            state.advance(false, false),
            SplitVolumeStep::Interrupted
        ));
        assert!(state.is_pending());
    }

    /// The property the legacy split paths need: however many fragments a
    /// member has, only ONE is open at any moment. Eagerly building a reader
    /// per fragment is what made a ~300-volume RAR4 member fail on `EMFILE`
    /// before it read a byte.
    #[test]
    fn lazy_chained_reader_holds_one_fragment_open_at_a_time() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct Counted {
            inner: Cursor<Vec<u8>>,
            live: Arc<AtomicUsize>,
        }
        impl Read for Counted {
            fn read(&mut self, out: &mut [u8]) -> Result<usize> {
                self.inner.read(out)
            }
        }
        impl Drop for Counted {
            fn drop(&mut self) {
                self.live.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let openers: Vec<FragmentOpener> = (0..8u8)
            .map(|index| {
                let live = Arc::clone(&live);
                let peak = Arc::clone(&peak);
                Box::new(move || {
                    let open = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(open, Ordering::SeqCst);
                    Ok(Box::new(Counted {
                        inner: Cursor::new(vec![index; 4]),
                        live,
                    }) as Box<dyn Read + Send>)
                }) as FragmentOpener
            })
            .collect();

        let mut out = Vec::new();
        LazyChainedReader::new(openers)
            .read_to_end(&mut out)
            .unwrap();

        assert_eq!(out.len(), 32, "every fragment is read, in order");
        assert!(out.chunks(4).enumerate().all(|(i, c)| c == [i as u8; 4]));
        assert_eq!(peak.load(Ordering::SeqCst), 1, "one fragment open at a time");
        assert_eq!(live.load(Ordering::SeqCst), 0, "and none left open at the end");
    }

    /// An empty fragment must not end the chain: a zero-length packed
    /// range is legal (a member whose split lands exactly on a volume
    /// boundary), and stopping there would truncate the member.
    #[test]
    fn lazy_chained_reader_reads_past_an_empty_fragment() {
        let openers: Vec<FragmentOpener> = vec![
            Box::new(|| Ok(Box::new(Cursor::new(b"one".to_vec())) as Box<dyn Read + Send>)),
            Box::new(|| Ok(Box::new(Cursor::new(Vec::new())) as Box<dyn Read + Send>)),
            Box::new(|| Ok(Box::new(Cursor::new(b"two".to_vec())) as Box<dyn Read + Send>)),
        ];
        let mut out = Vec::new();
        LazyChainedReader::new(openers)
            .read_to_end(&mut out)
            .unwrap();

        assert_eq!(out, b"onetwo");
    }
}

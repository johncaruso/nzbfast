use super::{blake2sp, Archive, ExtractedEntryMeta, FileHeader, FileRedirection};
use crate::codec::rar50::{DecodeMode, DecodedChunk, StreamDecodeError, Unpack50Decoder};
use crate::crc32::{crc32, Crc32};
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::error::{Error, Result};
use crate::volume_extract::{ChainedReader, SplitVolumeState, SplitVolumeStep};
use std::io::{Read, Write};

// Filtered RAR5 members still need whole-member byte transforms. Members at or
// below this boundary use the buffered path, while larger members stream once
// and reject filtered streams through the codec's typed sentinel.
#[cfg(not(test))]
const BUFFERED_DECODE_LIMIT: u64 = 512 * 1024 * 1024;
#[cfg(test)]
const BUFFERED_DECODE_LIMIT: u64 = 1024;

// Default ceiling on the streaming match window. RAR 7 dictionaries reach far
// past what a typical host can allocate (up to 64 GiB), and the streaming ring
// grows toward the declared dictionary; 1 GiB covers every real-world preset up
// to `-md1g` while capping the pathological cases at a ~2 GiB ring. Callers
// override via `ArchiveReadOptions::rar50_max_window`.
const DEFAULT_STREAM_WINDOW_LIMIT: u64 = 1024 * 1024 * 1024;

impl FileHeader {
    fn crypto_with_password(&self, password: Option<&[u8]>) -> Result<Option<Rar50Keys>> {
        if !self.encrypted {
            return Ok(None);
        }
        if let Some(crypto) = &self.crypto {
            return Ok(Some(crypto.keys.clone()));
        }
        let password = password.ok_or(Error::NeedPassword)?;
        let encryption = self.encryption.as_ref().ok_or(Error::InvalidHeader(
            "RAR 5 encrypted file is missing encryption record",
        ))?;
        if encryption.version != 0 {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file encryption version",
            });
        }
        let keys = Rar50Keys::derive(password, encryption.salt, encryption.kdf_count)
            .map_err(super::map_rar50_crypto_error)?;
        if let Some(check_value) = encryption.check_value {
            keys.check_password(&check_value)
                .map_err(super::map_rar50_crypto_error)?;
        }
        Ok(Some(keys))
    }

    fn encryption_iv(&self) -> Result<[u8; 16]> {
        if let Some(crypto) = &self.crypto {
            return Ok(crypto.iv);
        }
        self.encryption
            .as_ref()
            .map(|encryption| encryption.iv)
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption record",
            ))
    }

    fn packed_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Rar50Keys>)> {
        let (mut reader, keys) = self.packed_reader_with_password(archive, password)?;
        let mut packed = Vec::new();
        reader.read_to_end(&mut packed)?;
        Ok((packed, keys))
    }

    fn packed_reader_with_password<'a>(
        &self,
        archive: &'a Archive,
        password: Option<&[u8]>,
    ) -> Result<(Box<dyn Read + Send + 'a>, Option<Rar50Keys>)> {
        let reader = archive.range_reader(self.block.data_range.clone())?;
        if !self.encrypted {
            return Ok((reader, None));
        }
        if !self.packed_size().is_multiple_of(16) {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted file payload is not block aligned",
            ));
        }
        let keys = self
            .crypto_with_password(password)?
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption keys",
            ))?;
        let reader = Rar50DecryptingReader::new(reader, keys.key, self.encryption_iv()?);
        Ok((Box::new(reader), Some(keys)))
    }

    fn verify_integrity_with_keys(&self, data: &[u8], keys: Option<&Rar50Keys>) -> Result<()> {
        // When both digests are requested and the buffer is large, compute
        // them on two threads — they are independent passes over `data`.
        let wants_blake2 = matches!(&self.hash, Some(hash) if hash.hash_type == 0);
        let parallel_digests = if self.data_crc32.is_some() && wants_blake2 && data.len() >= 1 << 22
        {
            Some(std::thread::scope(|scope| {
                let crc_task = scope.spawn(|| crc32(data));
                let hash_value = blake2sp::hash(data);
                let crc_value = crc_task.join().expect("crc32 digest thread panicked");
                (crc_value, hash_value)
            }))
        } else {
            None
        };

        if let Some(expected) = self.data_crc32 {
            let actual = match parallel_digests {
                Some((crc_value, _)) => crc_value,
                None => crc32(data),
            };
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(actual)
            } else {
                actual
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        let Some(hash) = &self.hash else {
            return Ok(());
        };
        match hash.hash_type {
            0 if hash.data.len() == 32 => {
                let actual = match parallel_digests {
                    Some((_, hash_value)) => hash_value,
                    None => blake2sp::hash(data),
                };
                let actual = if self.uses_hash_mac() {
                    let keys = keys.ok_or(Error::InvalidHeader(
                        "RAR 5 encrypted hash MAC needs encryption keys",
                    ))?;
                    keys.mac_hash32(actual)
                } else {
                    actual
                };
                if constant_time_eq(&hash.data, &actual) {
                    Ok(())
                } else {
                    Err(Error::HashMismatch { hash_type: 0 })
                }
            }
            0 => Err(Error::InvalidHeader(
                "RAR 5 BLAKE2sp hash record has invalid length",
            )),
            _ => Ok(()),
        }
    }

    fn verify_streaming_integrity(
        &self,
        crc: Crc32,
        hash: Option<([u8; 32], blake2sp::Hasher)>,
        keys: Option<&Rar50Keys>,
    ) -> Result<()> {
        if let Some(expected) = self.data_crc32 {
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        if let Some((expected, hasher)) = hash {
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if !constant_time_eq(&expected, &actual) {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: self.is_directory(),
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut session = DecoderSession::new_with_password(password, BUFFERED_DECODE_LIMIT, DEFAULT_STREAM_WINDOW_LIMIT);
        session.write_file_to(archive, self, out)
    }

    pub(crate) fn decoded_data_unverified(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut decoder = Unpack50Decoder::new();
        Ok(self
            .decoded_data_with_decoder(archive, &mut decoder, password)?
            .data)
    }

    /// `decoded_data_unverified` with a ceiling on the DECLARED output size.
    ///
    /// The buffered decode path sizes its output from `self.unpacked_size`,
    /// which is a header field the archive author chooses, and the unverified
    /// entry point above consults neither `buffered_decode_limit` nor the
    /// stream window limit that the ordinary extraction path applies. So a
    /// small, perfectly parseable archive carrying a highly compressible
    /// member that declares a huge unpacked size decodes until the allocation
    /// fails - and Rust answers that with abort.
    ///
    /// That matters for service records specifically: they are decoded
    /// automatically, before any content check, on a path a damaged download
    /// reaches by itself.
    pub(crate) fn decoded_data_unverified_bounded(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        limit: u64,
    ) -> Result<Vec<u8>> {
        // Both sides are checked: the declared output, AND the packed input
        // that gets buffered whole to produce it. Bounding only the output
        // leaves the input allocation unchecked.
        if self.unpacked_size > limit {
            return Err(Error::Rar50BufferedDecodeLimitExceeded {
                limit,
                required: self.unpacked_size,
            });
        }
        if self.packed_size() > limit {
            return Err(Error::Rar50BufferedDecodeLimitExceeded {
                limit,
                required: self.packed_size(),
            });
        }
        self.decoded_data_unverified(archive, password)
    }

    fn decoded_data_with_decoder(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
    ) -> Result<DecodedData> {
        let (packed, keys) = self.packed_data_with_password(archive, password)?;
        let data = self.decode_packed_with_decoder(&packed, decoder)?;
        Ok(DecodedData { data, keys })
    }

    fn decoded_data_with_mode(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
        mode: DecodeMode,
    ) -> Result<DecodedData> {
        let (packed, keys) = self.packed_data_with_password(archive, password)?;
        let data = self.decode_packed_with_decoder_mode(&packed, decoder, mode)?;
        Ok(DecodedData { data, keys })
    }

    fn decode_packed_with_decoder(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
    ) -> Result<Vec<u8>> {
        self.decode_packed_with_decoder_mode(packed, decoder, DecodeMode::Lz)
    }

    fn decode_packed_with_decoder_mode(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            if self.encrypted {
                let unpacked_size = usize::try_from(self.unpacked_size).map_err(|_| {
                    Error::InvalidHeader("RAR 5 unpacked size overflows host address size")
                })?;
                if packed.len() < unpacked_size {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file is shorter than unpacked size",
                    ));
                }
                if packed[unpacked_size..].iter().any(|&byte| byte != 0) {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file has non-zero padding",
                    ));
                }
                return Ok(packed[..unpacked_size].to_vec());
            }
            if packed.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(packed.to_vec());
        }
        if self.unpacked_size == 0 && packed.is_empty() {
            return Ok(Vec::new());
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = checked_unpacked_size(self.unpacked_size)?;
        match decoder.decode_member_with_dictionary(
            packed,
            info.algorithm_version,
            output_size,
            dictionary_size,
            info.solid,
            mode,
        ) {
            Ok(data) => Ok(data),
            Err(error) => self.map_truncated_unverified_payload(error),
        }
    }

    fn map_truncated_unverified_payload(&self, error: crate::codec::Error) -> Result<Vec<u8>> {
        if matches!(error, crate::codec::Error::NeedMoreInput)
            && self.data_crc32.is_none()
            && self.hash.is_none()
        {
            return Ok(Vec::new());
        }
        Err(Error::from(error))
    }

    fn stream_packed_with_decoder<R: Read + Send>(
        &self,
        packed: &mut R,
        keys: Option<&Rar50Keys>,
        decoder: &mut Unpack50Decoder,
        buffered_decode_limit: u64,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if self.is_stored() {
            return Err(Error::InvalidHeader(
                "RAR 5 stored file does not use streaming compressed decode",
            ));
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = usize::try_from(self.unpacked_size)
            .map_err(|_| Error::InvalidHeader("RAR 5 unpacked size overflows host address size"))?;
        let mut crc = Crc32::new();
        let mut hash = streaming_hash_verifier(self)?;

        // Pipeline: the decoder runs on a spawned thread and hands coalesced
        // ~1 MB buffers over a bounded channel; checksumming and writing stay
        // on the calling thread (so `writer` needs no Send bound). A small
        // recycling pool bounds the extra memory and provides backpressure.
        const PIPE_BUF: usize = 1 << 20;
        const POOL_BUFFERS: usize = 3;
        enum PipeChunk {
            Data(Vec<u8>),
            Repeated { byte: u8, len: usize },
        }
        fn pipe_closed<T>(_: T) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "extraction pipeline closed")
        }

        let (data_tx, data_rx) = std::sync::mpsc::sync_channel::<PipeChunk>(POOL_BUFFERS + 1);
        let (pool_tx, pool_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        for _ in 0..POOL_BUFFERS {
            let _ = pool_tx.send(Vec::with_capacity(PIPE_BUF));
        }

        let mut write_error: Option<Error> = None;
        let decode_result = std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let mut current = pool_rx
                    .recv()
                    .map_err(|error| StreamDecodeError::Sink(pipe_closed(error)))?;
                let result = decoder.decode_member_from_reader_with_dictionary_to_sink(
                    packed,
                    info.algorithm_version,
                    output_size,
                    dictionary_size,
                    info.solid,
                    buffered_decode_limit,
                    |chunk| -> std::io::Result<()> {
                        match chunk {
                            DecodedChunk::Bytes(mut bytes) => {
                                while !bytes.is_empty() {
                                    let take = (PIPE_BUF - current.len()).min(bytes.len());
                                    current.extend_from_slice(&bytes[..take]);
                                    bytes = &bytes[take..];
                                    if current.len() == PIPE_BUF {
                                        data_tx
                                            .send(PipeChunk::Data(std::mem::take(&mut current)))
                                            .map_err(pipe_closed)?;
                                        current = pool_rx.recv().map_err(pipe_closed)?;
                                    }
                                }
                                Ok(())
                            }
                            DecodedChunk::Repeated { byte, len } => {
                                if !current.is_empty() {
                                    data_tx
                                        .send(PipeChunk::Data(std::mem::take(&mut current)))
                                        .map_err(pipe_closed)?;
                                    current = pool_rx.recv().map_err(pipe_closed)?;
                                }
                                data_tx
                                    .send(PipeChunk::Repeated { byte, len })
                                    .map_err(pipe_closed)
                            }
                        }
                    },
                );
                if result.is_ok() && !current.is_empty() {
                    data_tx
                        .send(PipeChunk::Data(current))
                        .map_err(pipe_closed)
                        .map_err(StreamDecodeError::Sink)?;
                }
                result
            });

            for chunk in data_rx {
                let outcome = match chunk {
                    PipeChunk::Data(buffer) => {
                        crc.update(&buffer);
                        if let Some((_, hasher)) = &mut hash {
                            hasher.update(&buffer);
                        }
                        let outcome = writer.write_all(&buffer);
                        let mut buffer = buffer;
                        buffer.clear();
                        let _ = pool_tx.send(buffer);
                        outcome
                    }
                    PipeChunk::Repeated { byte, len } => {
                        write_repeated_chunk(writer, &mut crc, &mut hash, byte, len)
                    }
                };
                if let Err(error) = outcome {
                    write_error = Some(Error::from(error));
                    break;
                }
            }
            // Receiver is dropped here (loop finished or broke), which
            // unblocks a producer stuck on send; it then errors out and
            // the join below collects it.
            handle.join().expect("streaming decode thread panicked")
        });

        if let Some(error) = write_error {
            return Err(error);
        }
        decode_result.map_err(|error| match error {
            StreamDecodeError::Decode(crate::codec::Error::WindowLimitExceeded {
                limit,
                required,
            }) => Error::Rar50WindowLimitExceeded { limit, required },
            StreamDecodeError::Decode(error) => Error::from(error),
            StreamDecodeError::FilteredMember => Error::Rar50BufferedDecodeLimitExceeded {
                limit: buffered_decode_limit,
                required: self.unpacked_size,
            },
            StreamDecodeError::Sink(error) => Error::from(error),
        })?;
        self.verify_streaming_integrity(crc, hash, keys)
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let (mut reader, keys) = self
            .packed_reader_with_password(archive, password)
            .map_err(|error| self.entry_error("decoding", error))?;
        let mut crc = Crc32::new();
        let mut hash =
            streaming_hash_verifier(self).map_err(|error| self.entry_error("decoding", error))?;
        let mut written = 0u64;

        // Pipeline: reading (and decrypting) runs on a spawned thread;
        // padding checks, checksums, and writing stay on the calling thread.
        const STORED_PIPE_BUF: usize = 1 << 20;
        const STORED_POOL: usize = 3;
        let (data_tx, data_rx) =
            std::sync::mpsc::sync_channel::<std::io::Result<Vec<u8>>>(STORED_POOL + 1);
        let (pool_tx, pool_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        for _ in 0..STORED_POOL {
            let _ = pool_tx.send(vec![0u8; STORED_PIPE_BUF]);
        }

        let mut stage_error: Option<Error> = None;
        let mut stage_operation = "decoding";
        std::thread::scope(|scope| {
            scope.spawn(move || {
                loop {
                    let Ok(mut buf) = pool_rx.recv() else {
                        return;
                    };
                    buf.resize(STORED_PIPE_BUF, 0);
                    match reader.read(&mut buf) {
                        Ok(0) => return,
                        Ok(count) => {
                            buf.truncate(count);
                            if data_tx.send(Ok(buf)).is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            let _ = data_tx.send(Err(error));
                            return;
                        }
                    }
                }
            });

            for received in data_rx {
                let buf = match received {
                    Ok(buf) => buf,
                    Err(error) => {
                        stage_error = Some(Error::from(error));
                        stage_operation = "decoding";
                        break;
                    }
                };
                if let Err((operation, error)) =
                    self.consume_stored_chunk(&buf, &mut written, &mut crc, &mut hash, writer)
                {
                    stage_error = Some(error);
                    stage_operation = operation;
                    break;
                }
                let _ = pool_tx.send(buf);
            }
        });
        if let Some(error) = stage_error {
            return Err(self.entry_error(stage_operation, error));
        }

        if written != self.unpacked_size {
            return Err(self.entry_error(
                "decoding",
                Error::InvalidHeader("RAR 5 stored file has mismatched packed and unpacked sizes"),
            ));
        }
        self.verify_streaming_integrity(crc, hash, keys.as_ref())
            .map_err(|error| self.entry_error("verifying", error))
    }

    /// Padding check, checksum update, and write for one stored-file chunk.
    /// Returns the failing operation label alongside the error.
    fn consume_stored_chunk(
        &self,
        buf: &[u8],
        written: &mut u64,
        crc: &mut Crc32,
        hash: &mut Option<([u8; 32], blake2sp::Hasher)>,
        writer: &mut dyn Write,
    ) -> std::result::Result<(), (&'static str, Error)> {
        let remaining =
            usize::try_from(self.unpacked_size.saturating_sub(*written)).unwrap_or(usize::MAX);
        let chunk_len = buf.len().min(remaining);
        let chunk = &buf[..chunk_len];
        if self.encrypted && buf[chunk_len..].iter().any(|&byte| byte != 0) {
            return Err((
                "decoding",
                Error::InvalidHeader("RAR 5 encrypted stored file has non-zero padding"),
            ));
        }
        *written = written
            .checked_add(chunk.len() as u64)
            .ok_or(Error::InvalidHeader("RAR 5 stored size overflows"))
            .map_err(|error| ("decoding", error))?;
        crc.update(chunk);
        if let Some((_, hasher)) = hash {
            hasher.update(chunk);
        }
        writer
            .write_all(chunk)
            .map_err(Error::from)
            .map_err(|error| ("writing", error))?;
        Ok(())
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        error.at_entry(self.name.clone(), operation)
    }
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    written: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buf)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn is_streaming_filter_bail(error: &Error) -> bool {
    match error {
        Error::Rar50BufferedDecodeLimitExceeded { .. } => true,
        Error::AtEntry { source, .. } => is_streaming_filter_bail(source),
        _ => false,
    }
}

fn write_repeated_chunk(
    writer: &mut dyn Write,
    crc: &mut Crc32,
    hash: &mut Option<([u8; 32], blake2sp::Hasher)>,
    byte: u8,
    mut len: usize,
) -> std::io::Result<()> {
    let buffer = [byte; 64 * 1024];
    while len > 0 {
        let take = len.min(buffer.len());
        let chunk = &buffer[..take];
        writer.write_all(chunk)?;
        if byte == 0 {
            crc.update_zeroes(take as u64);
        } else {
            crc.update(chunk);
        }
        if let Some((_, hasher)) = hash.as_mut() {
            hasher.update(chunk);
        }
        len -= take;
    }
    Ok(())
}

impl Archive {
    pub fn extract_to<F>(&self, options: crate::ArchiveReadOptions<'_>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_impl(options, &mut open, &mut |_, _| Ok(()), false)
    }

    pub fn extract_to_with_redirections<F, R>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        mut open: F,
        mut redirect: R,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
        R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
    {
        self.extract_to_impl(options, &mut open, &mut redirect, true)
    }

    fn extract_to_impl<F, R>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        open: &mut F,
        redirect: &mut R,
        emit_redirections: bool,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
        R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
    {
        let buffered_decode_limit = rar50_buffered_decode_limit(options);
        let mut session = DecoderSession::new_with_password(
            options.password,
            buffered_decode_limit,
            rar50_max_window(options),
        );
        for file in self.files() {
            if let Some(redirection) = &file.redirection {
                if emit_redirections {
                    redirect(&file.metadata(), redirection)?;
                }
                continue;
            }
            if file.is_split_before() || file.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry requires multivolume extraction",
                ));
            }
            let meta = file.metadata();
            let mut writer = open(&meta)?;
            if !meta.is_directory {
                session.write_file_to(self, file, &mut writer)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "parallel")]
    pub fn extract_to_parallel_buffered<F>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        if self.main.is_solid()
            || self.files().any(|file| {
                file.is_split_before()
                    || file.is_split_after()
                    || file.should_stream_decode(rar50_buffered_decode_limit(options))
                    || file.decoded_compression_info().is_ok_and(|info| info.solid)
            })
        {
            return self.extract_to(options, open);
        }

        let password = options.password;
        let buffered_decode_limit = rar50_buffered_decode_limit(options);
        let files: Vec<_> = self.files().collect();
        if files.len() < 2 {
            return self.extract_to(options, open);
        }
        let entries = crate::parallel::map_collect(files, |file| {
            decode_parallel_entry(self, file, password, buffered_decode_limit)
        })?;
        for entry in entries {
            write_parallel_entry(entry, &mut open, &mut |_, _| Ok(()))?;
        }
        Ok(())
    }
}

#[cfg(feature = "parallel")]
enum ParallelExtractedEntry {
    Directory(ExtractedEntryMeta),
    File {
        meta: ExtractedEntryMeta,
        data: Vec<u8>,
    },
    Redirection {
        meta: ExtractedEntryMeta,
        redirection: FileRedirection,
    },
}

#[cfg(feature = "parallel")]
fn decode_parallel_entry(
    archive: &Archive,
    file: &FileHeader,
    password: Option<&[u8]>,
    buffered_decode_limit: u64,
) -> Result<ParallelExtractedEntry> {
    if let Some(redirection) = &file.redirection {
        return Ok(ParallelExtractedEntry::Redirection {
            meta: file.metadata(),
            redirection: redirection.clone(),
        });
    }
    if file.is_split_before() || file.is_split_after() {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry requires multivolume extraction",
        ));
    }
    let meta = file.metadata();
    if meta.is_directory {
        return Ok(ParallelExtractedEntry::Directory(meta));
    }
    let mut data = Vec::new();
    let mut session = DecoderSession::new_with_password(password, buffered_decode_limit, DEFAULT_STREAM_WINDOW_LIMIT);
    session.write_file_to(archive, file, &mut data)?;
    Ok(ParallelExtractedEntry::File { meta, data })
}

#[cfg(feature = "parallel")]
fn write_parallel_entry<F, R>(
    entry: ParallelExtractedEntry,
    open: &mut F,
    redirect: &mut R,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    match entry {
        ParallelExtractedEntry::Directory(meta) => {
            let _ = open(&meta)?;
        }
        ParallelExtractedEntry::File { meta, data } => {
            let mut writer = open(&meta)?;
            writer.write_all(&data)?;
        }
        ParallelExtractedEntry::Redirection { meta, redirection } => {
            redirect(&meta, &redirection)?;
        }
    }
    Ok(())
}

struct DecodedData {
    data: Vec<u8>,
    keys: Option<Rar50Keys>,
}

struct DecoderSession<'a> {
    decoder: Unpack50Decoder,
    password: Option<&'a [u8]>,
    buffered_decode_limit: u64,
}

impl<'a> DecoderSession<'a> {
    fn new_with_password(
        password: Option<&'a [u8]>,
        buffered_decode_limit: u64,
        max_window: u64,
    ) -> Self {
        let mut decoder = Unpack50Decoder::new();
        decoder.set_window_limit(usize::try_from(max_window).unwrap_or(usize::MAX));
        Self {
            decoder,
            password,
            buffered_decode_limit,
        }
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if file.is_stored() {
            return file.write_stored_to(archive, self.password, writer);
        }
        // Non-solid archives never reference a previous member's window, so
        // skip history retention (and the decoder clones below that exist
        // only to protect it) — saves up to dictionary-size copies per file.
        let solid_archive = archive.main.is_solid();
        self.decoder.set_retain_history(solid_archive);
        if file.should_stream_decode(self.buffered_decode_limit) {
            let mut counting = CountingWriter { inner: writer, written: 0 };
            match self.stream_file_to(archive, file, &mut counting) {
                // The streaming decoder bails on pathological filters
                // (over-long hold spans, partial overlaps). If nothing
                // reached the writer yet and the member fits the buffered
                // ceiling, decode it buffered instead.
                Err(error)
                    if counting.written == 0
                        && file.unpacked_size <= self.buffered_decode_limit
                        && is_streaming_filter_bail(&error) => {}
                other => return other,
            }
        }
        // Solid members rewind via an O(1) checkpoint when the filtered
        // output fails verification - the old decoder clone copied the
        // whole multi-MB solid window once per member. Non-solid members
        // retry on a fresh decoder as before (they carry no state).
        let checkpoint = solid_archive.then(|| self.decoder.solid_checkpoint());
        let decoded = self
            .decoded_file_data(archive, file)
            .map_err(|error| file.entry_error("decoding", error))?;
        let decoded = match file.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref()) {
            Ok(()) => decoded,
            Err(filtered_error) => {
                let unfiltered = if let Some(cp) = &checkpoint {
                    self.decoder.restore_checkpoint(cp);
                    file.decoded_data_with_mode(
                        archive,
                        &mut self.decoder,
                        self.password,
                        DecodeMode::LzNoFilters,
                    )
                    .map_err(|error| file.entry_error("decoding", error))?
                } else {
                    let mut fresh = Unpack50Decoder::new();
                    let unfiltered = file
                        .decoded_data_with_mode(
                            archive,
                            &mut fresh,
                            self.password,
                            DecodeMode::LzNoFilters,
                        )
                        .map_err(|error| file.entry_error("decoding", error))?;
                    self.decoder = fresh;
                    unfiltered
                };
                file.verify_integrity_with_keys(&unfiltered.data, unfiltered.keys.as_ref())
                    .map_err(|_| file.entry_error("verifying", filtered_error))?;
                unfiltered
            }
        };
        if solid_archive {
            // Verified and final: reclaim the window buffer's dead front.
            self.decoder.commit_member();
        }
        writer
            .write_all(&decoded.data)
            .map_err(Error::from)
            .map_err(|error| file.entry_error("writing", error))
    }

    fn stream_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let (mut packed, keys) = file
            .packed_reader_with_password(archive, self.password)
            .map_err(|error| file.entry_error("reading", error))?;
        if archive.main.is_solid() {
            // Work on a clone so a failed stream leaves the session's
            // decoder (and its solid history) untouched for a retry.
            // Compact first so the clone carries only the live window,
            // not the offset buffer's dead front.
            self.decoder.commit_member();
            let mut streaming_decoder = self.decoder.clone();
            file.stream_packed_with_decoder(
                &mut packed,
                keys.as_ref(),
                &mut streaming_decoder,
                self.buffered_decode_limit,
                writer,
            )
            .map_err(|error| file.entry_error("decoding", error))?;
            self.decoder = streaming_decoder;
        } else {
            file.stream_packed_with_decoder(
                &mut packed,
                keys.as_ref(),
                &mut self.decoder,
                self.buffered_decode_limit,
                writer,
            )
            .map_err(|error| file.entry_error("decoding", error))?;
        }
        Ok(())
    }

    fn decoded_file_data(&mut self, archive: &Archive, file: &FileHeader) -> Result<DecodedData> {
        file.decoded_data_with_decoder(archive, &mut self.decoder, self.password)
    }

    fn split_decryptor(
        &self,
        split: &PendingSplitRefs,
        volumes: &[Archive],
    ) -> Result<Option<SplitDecryptor>> {
        split.split_decryptor(volumes, self.password)
    }

    fn decode_split(
        &mut self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Vec<u8>> {
        final_file.decode_split_with_decoder(volumes, split, &mut self.decoder, decryptor)
    }
}

// Streaming decode (ring window + pipelined hash/write) outperforms the
// buffered path well before memory becomes a concern, so members above this
// size stream by default; `buffered_decode_limit` remains the ceiling for
// the buffered fallback (pathological filters) and can only lower the bar.
const STREAMING_PREFERRED_MIN: u64 = 4 * 1024 * 1024;

impl FileHeader {
    fn should_stream_decode(&self, buffered_decode_limit: u64) -> bool {
        !self.is_stored() && self.unpacked_size > buffered_decode_limit.min(STREAMING_PREFERRED_MIN)
    }
}

fn rar50_buffered_decode_limit(options: crate::ArchiveReadOptions<'_>) -> u64 {
    options
        .rar50_buffered_decode_limit
        .unwrap_or(BUFFERED_DECODE_LIMIT)
}

fn rar50_max_window(options: crate::ArchiveReadOptions<'_>) -> u64 {
    options
        .rar50_max_window
        .unwrap_or(DEFAULT_STREAM_WINDOW_LIMIT)
}

/// Streams a RAR 5 multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_impl(volumes, options, &mut open, &mut |_, _| Ok(()), false)
}

pub fn extract_volumes_to_with_redirections<F, R>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut redirect: R,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    extract_volumes_to_impl(volumes, options, &mut open, &mut redirect, true)
}

fn extract_volumes_to_impl<F, R>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: &mut F,
    redirect: &mut R,
    emit_redirections: bool,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }

    // Non-solid sets with several small compressed members decode them on a
    // worker pool (members are independent; unrar streams sequentially and
    // cannot). Writers and callbacks stay on this thread in archive order.
    #[cfg(feature = "parallel")]
    if let Some(plan) = member_pool_plan(volumes, options) {
        return extract_volumes_pooled(volumes, options, open, redirect, emit_redirections, plan);
    }

    let password = options.password;
    let mut split = SplitVolumeState::new();
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let mut session = DecoderSession::new_with_password(
        password,
        buffered_decode_limit,
        rar50_max_window(options),
    );
    // Members already extracted as part of a solid chain group, and the
    // kill-switch a failed chain flips (the group then retries serially,
    // and no further chains are attempted for this set).
    #[cfg(feature = "parallel")]
    let mut chained: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    #[cfg(feature = "parallel")]
    let mut chain_disabled = false;

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    if let Some(redirection) = &file.redirection {
                        if emit_redirections {
                            redirect(&file.metadata(), redirection)?;
                        }
                        continue;
                    }
                    #[cfg(feature = "parallel")]
                    {
                        if chained.contains(&(volume_index, file_index)) {
                            continue;
                        }
                        // Solid archives: a run of chainable members decodes
                        // as ONE stream through the MT pipeline instead of
                        // member-by-member on one thread. Any chain failure
                        // restores the pre-group state and falls through to
                        // the serial path, which re-decodes the group with
                        // its exact error semantics (writers are re-opened,
                        // so partially chained output is rewritten).
                        if !chain_disabled && archive.main.is_solid() && chain_member_shape(file)
                        {
                            let members =
                                collect_solid_chain(volumes, (volume_index, file_index));
                            let total: usize =
                                members.iter().map(|m| m.output_size).sum();
                            if members.len() >= 2
                                && Unpack50Decoder::solid_chain_worthwhile(total)
                            {
                                let snapshot = session.decoder.snapshot_solid_state();
                                match stream_solid_chain(&mut session, volumes, &members, open)
                                {
                                    Ok(()) => {
                                        for member in &members {
                                            chained
                                                .insert((member.volume_index, member.file_index));
                                        }
                                        continue;
                                    }
                                    Err(_) => {
                                        session.decoder.restore_solid_state(snapshot);
                                        chain_disabled = true;
                                    }
                                }
                            }
                        }
                    }
                    let meta = file.metadata();
                    let mut writer = open(&meta)?;
                    if !meta.is_directory {
                        session.write_file_to(archive, file, &mut writer)?;
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(volume_index, file_index);
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(volume_index, file_index);
                    completed.write_to(volumes, file, &mut session, &mut *open)?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

/// Streams a RAR 5 multivolume set whose volumes become available one at a
/// time, extracting each volume's members as soon as that volume parses.
///
/// `next_volume(index)` supplies volume `index`, blocking as needed (e.g. an
/// `Archive::parse_stream` call over a still-arriving source), and returns
/// `None` after the last volume. Members of volume k extract before volume
/// k+1 is requested, so extraction chases a progressive download at volume
/// granularity: while volume k's members decode, the bytes of volume k+1
/// keep arriving, and the next `next_volume` call blocks only for whatever
/// has not landed yet. Split members spanning volumes j..=k decode when
/// volume k appears, reading earlier fragments back through the retained
/// volumes, with the same semantics as `extract_volumes_to`.
///
/// Decoding is serial by design: the parallel member-pool and solid-chain
/// plans inspect the whole set up front, and a chasing extraction is bound
/// by arrival rate rather than decode rate.
pub fn extract_volume_sequence_to<P, F>(
    mut next_volume: P,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    P: FnMut(usize) -> Result<Option<Archive>>,
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let password = options.password;
    let mut split = SplitVolumeState::new();
    let mut session = DecoderSession::new_with_password(
        password,
        rar50_buffered_decode_limit(options),
        rar50_max_window(options),
    );
    let mut volumes: Vec<Archive> = Vec::new();

    loop {
        let volume_index = volumes.len();
        let Some(archive) = next_volume(volume_index)? else {
            break;
        };
        volumes.push(archive);
        let archive = &volumes[volume_index];
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    if file.redirection.is_some() {
                        continue;
                    }
                    let meta = file.metadata();
                    let mut writer = open(&meta)?;
                    if !meta.is_directory {
                        session.write_file_to(archive, file, &mut writer)?;
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(volume_index, file_index);
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(volume_index, file_index);
                    completed.write_to(&volumes, file, &mut session, &mut open)?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }
    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

// --- solid-chain MT decode (solid sets: one stream, cut at boundaries) -----
//
// A solid group is ONE continuous compressed stream split at member
// boundaries: tables, rep state, and the LZ window all carry across
// members. Chaining the members' packed readers through the existing MT
// scan/tape pipeline decodes the whole group with the worker pool the big
// single members already enjoy; this consumer cuts the emitted byte stream
// at member boundaries, opening each writer and verifying each member's
// digests (CRC32/BLAKE2sp) as the bytes stream past - exactly what the
// serial per-member path checks, at the same points.

/// One member of a solid chain group.
#[cfg(feature = "parallel")]
struct ChainMember<'a> {
    volume_index: usize,
    file_index: usize,
    file: &'a FileHeader,
    output_size: usize,
}

/// Is `file` shaped for chain membership? Splits, stored members,
/// directories, redirections, encrypted members (keyed digest MACs stay on
/// the serial path), and zero-size members all cut the chain.
#[cfg(feature = "parallel")]
fn chain_member_shape(file: &FileHeader) -> bool {
    file.redirection.is_none()
        && !file.is_split_before()
        && !file.is_split_after()
        && !file.is_directory()
        && !file.is_stored()
        && !file.encrypted
        && file.unpacked_size > 0
        && usize::try_from(file.unpacked_size).is_ok()
}

/// Collect the maximal solid chain group starting at `start` (inclusive):
/// consecutive members of matching shape, same algorithm and dictionary,
/// every member after the first carrying the solid flag. Stops at the
/// first ineligible member.
#[cfg(feature = "parallel")]
fn collect_solid_chain<'a>(
    volumes: &'a [Archive],
    start: (usize, usize),
) -> Vec<ChainMember<'a>> {
    let mut members: Vec<ChainMember<'a>> = Vec::new();
    let mut base: Option<(u8, u64)> = None; // (algorithm_version, dictionary)
    'volumes: for (volume_index, archive) in volumes.iter().enumerate().skip(start.0) {
        for (file_index, file) in archive.files().enumerate() {
            if volume_index == start.0 && file_index < start.1 {
                continue;
            }
            if !chain_member_shape(file) {
                break 'volumes;
            }
            let Ok(info) = file.decoded_compression_info() else {
                break 'volumes;
            };
            match base {
                None => base = Some((info.algorithm_version, info.dictionary_size)),
                Some((alg, dict)) => {
                    if info.algorithm_version != alg || info.dictionary_size != dict || !info.solid
                    {
                        break 'volumes;
                    }
                }
            }
            members.push(ChainMember {
                volume_index,
                file_index,
                file,
                output_size: file.unpacked_size as usize,
            });
        }
    }
    members
}

/// Decode a chain group through the MT pipeline and stream each member out
/// through `open` in archive order, verifying digests at each boundary.
#[cfg(feature = "parallel")]
fn stream_solid_chain<F>(
    session: &mut DecoderSession<'_>,
    volumes: &[Archive],
    members: &[ChainMember<'_>],
    open: &mut F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let first_info = members[0].file.decoded_compression_info()?;
    let dictionary_size = usize::try_from(first_info.dictionary_size)
        .map_err(|_| Error::InvalidHeader("RAR 5 dictionary size overflows host address size"))?;
    let total: usize = members.iter().map(|m| m.output_size).sum();
    // The window must persist for members after the group.
    session.decoder.set_retain_history(true);
    // A group under this budget takes the flat-apply fast path; larger
    // groups stream through the ring. Bounded separately from the member
    // flat limit so one solid group never holds more than this in memory.
    const CHAIN_FLAT_LIMIT: u64 = 256 << 20;
    let flat_limit = session.buffered_decode_limit.min(CHAIN_FLAT_LIMIT);

    // Same pipe as stream_packed_with_decoder: decode on a spawned thread,
    // checksum + write on this thread (writers are not Send).
    const PIPE_BUF: usize = 1 << 20;
    const POOL_BUFFERS: usize = 3;
    enum PipeChunk {
        Data(Vec<u8>),
        Repeated { byte: u8, len: usize },
    }
    fn pipe_closed<T>(_: T) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "extraction pipeline closed")
    }

    let (data_tx, data_rx) = std::sync::mpsc::sync_channel::<PipeChunk>(POOL_BUFFERS + 1);
    let (pool_tx, pool_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    for _ in 0..POOL_BUFFERS {
        let _ = pool_tx.send(Vec::with_capacity(PIPE_BUF));
    }

    let decoder = &mut session.decoder;
    let password = session.password;
    let mut consume_error: Option<Error> = None;
    let scope_outcome = std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            // Member readers, yielded to the scan in order. An open failure
            // ends the chain early (the shortfall surfaces as
            // NeedMoreInput); the real error rides back beside the result.
            let mut next = 0usize;
            let mut reader_error: Option<Error> = None;
            let mut next_input = || {
                let member = members.get(next)?;
                next += 1;
                match member
                    .file
                    .packed_reader_with_password(&volumes[member.volume_index], password)
                {
                    Ok((reader, _keys)) => Some(reader),
                    Err(error) => {
                        reader_error = Some(error);
                        None
                    }
                }
            };
            let mut current = match pool_rx.recv() {
                Ok(buffer) => buffer,
                Err(error) => {
                    return (Err(StreamDecodeError::Sink(pipe_closed(error))), None);
                }
            };
            let result = decoder.decode_solid_chain_to_sink(
                &mut next_input,
                first_info.algorithm_version,
                total,
                dictionary_size,
                !first_info.solid,
                flat_limit,
                |chunk| -> std::io::Result<()> {
                    match chunk {
                        DecodedChunk::Bytes(mut bytes) => {
                            while !bytes.is_empty() {
                                let take = (PIPE_BUF - current.len()).min(bytes.len());
                                current.extend_from_slice(&bytes[..take]);
                                bytes = &bytes[take..];
                                if current.len() == PIPE_BUF {
                                    data_tx
                                        .send(PipeChunk::Data(std::mem::take(&mut current)))
                                        .map_err(pipe_closed)?;
                                    current = pool_rx.recv().map_err(pipe_closed)?;
                                }
                            }
                            Ok(())
                        }
                        DecodedChunk::Repeated { byte, len } => {
                            if !current.is_empty() {
                                data_tx
                                    .send(PipeChunk::Data(std::mem::take(&mut current)))
                                    .map_err(pipe_closed)?;
                                current = pool_rx.recv().map_err(pipe_closed)?;
                            }
                            data_tx
                                .send(PipeChunk::Repeated { byte, len })
                                .map_err(pipe_closed)
                        }
                    }
                },
            );
            let result = if result.is_ok() && !current.is_empty() {
                data_tx
                    .send(PipeChunk::Data(current))
                    .map_err(pipe_closed)
                    .map_err(StreamDecodeError::Sink)
            } else {
                result
            };
            (result, reader_error)
        });

        // Consumer: route the byte stream across member boundaries.
        let mut cursor = 0usize; // member index
        let mut member_state: Option<(Box<dyn Write>, Crc32, Option<([u8; 32], blake2sp::Hasher)>, usize)> =
            None;
        let mut begin_member = |cursor: usize,
                                open: &mut F|
         -> Result<(Box<dyn Write>, Crc32, Option<([u8; 32], blake2sp::Hasher)>, usize)> {
            let member = &members[cursor];
            let writer = open(&member.file.metadata())?;
            Ok((
                writer,
                Crc32::new(),
                streaming_hash_verifier(member.file)?,
                member.output_size,
            ))
        };
        'consume: for chunk in data_rx.iter() {
            let mut chunk = match chunk {
                PipeChunk::Data(buffer) => ChunkCursor::Data(buffer, 0),
                PipeChunk::Repeated { byte, len } => ChunkCursor::Repeated { byte, len },
            };
            while chunk.remaining() > 0 {
                if member_state.is_none() {
                    if cursor >= members.len() {
                        consume_error = Some(Error::InvalidHeader(
                            "RAR 5 solid chain produced more bytes than its members declare",
                        ));
                        break 'consume;
                    }
                    match begin_member(cursor, open) {
                        Ok(state) => member_state = Some(state),
                        Err(error) => {
                            consume_error = Some(error);
                            break 'consume;
                        }
                    }
                }
                let (writer, crc, hash, remaining) =
                    member_state.as_mut().expect("member state just set");
                let take = (*remaining).min(chunk.remaining());
                let outcome = match &mut chunk {
                    ChunkCursor::Data(buffer, offset) => {
                        let slice = &buffer[*offset..*offset + take];
                        crc.update(slice);
                        if let Some((_, hasher)) = hash {
                            hasher.update(slice);
                        }
                        let outcome = writer.write_all(slice).map_err(Error::from);
                        *offset += take;
                        outcome
                    }
                    ChunkCursor::Repeated { byte, len } => {
                        let outcome =
                            write_repeated_chunk(writer.as_mut(), crc, hash, *byte, take)
                                .map_err(Error::from);
                        *len -= take;
                        outcome
                    }
                };
                if let Err(error) = outcome {
                    consume_error =
                        Some(members[cursor].file.entry_error("writing", error));
                    break 'consume;
                }
                *remaining -= take;
                if *remaining == 0 {
                    let (_writer, crc, hash, _) =
                        member_state.take().expect("member state present");
                    if let Err(error) = members[cursor]
                        .file
                        .verify_streaming_integrity(crc, hash, None)
                    {
                        consume_error =
                            Some(members[cursor].file.entry_error("verifying", error));
                        break 'consume;
                    }
                    cursor += 1;
                }
            }
            // Recycle the drained buffer so the producer never starves.
            if let ChunkCursor::Data(mut buffer, _) = chunk {
                buffer.clear();
                let _ = pool_tx.send(buffer);
            }
        }
        // Dropping the receiver here unblocks a producer stuck on send.
        drop(data_rx);
        let (decode, reader_error) =
            handle.join().expect("solid chain decode thread panicked");
        (decode, reader_error, cursor)
    });

    let (decode_result, reader_error, verified_members) = scope_outcome;
    if let Some(error) = consume_error {
        return Err(error);
    }
    let at = verified_members.min(members.len() - 1);
    if let Some(error) = reader_error {
        // A member's packed reader failed to open mid-chain; the decode
        // error below is just the resulting shortfall - surface the cause.
        return Err(members[at].file.entry_error("reading", error));
    }
    match decode_result {
        Ok(()) => {
            if verified_members == members.len() {
                Ok(())
            } else {
                // Decode declared success but the stream came up short.
                Err(members[at]
                    .file
                    .entry_error("decoding", Error::from(crate::codec::Error::NeedMoreInput)))
            }
        }
        Err(StreamDecodeError::Decode(crate::codec::Error::WindowLimitExceeded {
            limit,
            required,
        })) => Err(members[at].file.entry_error(
            "decoding",
            Error::Rar50WindowLimitExceeded { limit, required },
        )),
        Err(StreamDecodeError::Decode(error)) => {
            Err(members[at].file.entry_error("decoding", Error::from(error)))
        }
        Err(StreamDecodeError::FilteredMember) => Err(members[at].file.entry_error(
            "decoding",
            Error::InvalidHeader("RAR 5 solid chain member needs the buffered filter path"),
        )),
        Err(StreamDecodeError::Sink(error)) => Err(Error::from(error)),
    }
}

/// A pipe chunk being consumed across member boundaries.
#[cfg(feature = "parallel")]
enum ChunkCursor {
    Data(Vec<u8>, usize),
    Repeated { byte: u8, len: usize },
}

#[cfg(feature = "parallel")]
impl ChunkCursor {
    fn remaining(&self) -> usize {
        match self {
            Self::Data(buffer, offset) => buffer.len() - offset,
            Self::Repeated { len, .. } => *len,
        }
    }
}

// --- member-parallel decode pool (non-solid sets, small members) -----------
//
// Non-solid RAR5 members share no decoder state, so several can decode at
// once. The coordinator (caller thread) walks headers in archive order and
// owns every writer/callback; workers only turn packed bytes into verified
// member bytes. Results rejoin through a BTreeMap reorder, and a byte budget
// on decoded-but-unwritten members bounds RSS however fast the workers run
// ahead of the writer.

/// Ceiling on decoded-but-unwritten pooled bytes. The feeder blocks past
/// this, so a pathological archive of max-size pooled members cannot balloon
/// RSS. The tiny test value forces the backpressure path constantly.
#[cfg(all(feature = "parallel", not(test)))]
const POOL_INFLIGHT_BUDGET: u64 = 64 << 20;
#[cfg(all(feature = "parallel", test))]
const POOL_INFLIGHT_BUDGET: u64 = 8 * 1024;

/// One pooled member, resolved when the plan is built.
///
/// `Archive::files()` filters the block list, so it is not indexable:
/// recovering a member by ordinal walks the blocks from the start. The feeder
/// and every worker needed one member each, which made header lookup O(N²) in
/// the member count. Resolving once at plan time makes it O(1) per member.
#[cfg(feature = "parallel")]
struct PoolEntry<'a> {
    volume_index: usize,
    file: &'a FileHeader,
    unpacked_size: u64,
}

#[cfg(feature = "parallel")]
struct MemberPoolPlan<'a> {
    /// (volume_index, file_index) -> pool sequence number, archive order.
    seq_of: std::collections::HashMap<(usize, usize), usize>,
    /// Pool entries in feed order (archive order).
    order: Vec<PoolEntry<'a>>,
}

/// A member decodes on the pool when it is a regular compressed file that
/// would take the buffered serial path today: not split, not stored, not a
/// directory or redirection, and under the streaming threshold. Stored
/// members stay inline (their cost is I/O, not decode); streaming/MT members
/// stay inline (MT already uses the cores; trap: a big member must not be
/// stolen from inline-MT by the pool).
#[cfg(feature = "parallel")]
fn member_pool_eligible(file: &FileHeader, buffered_decode_limit: u64) -> bool {
    file.redirection.is_none()
        && !file.is_split_before()
        && !file.is_split_after()
        && !file.is_directory()
        && !file.is_stored()
        && !file.should_stream_decode(buffered_decode_limit)
}

/// Build the pool plan, or None when the set must take the serial path:
/// solid archives (members chain through the window), any per-file solid
/// flag, or fewer than two eligible members (a one-file archive must not
/// pay any pool cost).
#[cfg(feature = "parallel")]
fn member_pool_plan<'a>(
    volumes: &'a [Archive],
    options: crate::ArchiveReadOptions<'_>,
) -> Option<MemberPoolPlan<'a>> {
    if volumes.iter().any(|archive| archive.main.is_solid()) {
        return None;
    }
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let mut seq_of = std::collections::HashMap::new();
    let mut order = Vec::new();
    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            if file
                .decoded_compression_info()
                .is_ok_and(|info| info.solid)
            {
                return None;
            }
            if member_pool_eligible(file, buffered_decode_limit) {
                seq_of.insert((volume_index, file_index), order.len());
                order.push(PoolEntry {
                    volume_index,
                    file,
                    unpacked_size: file.unpacked_size,
                });
            }
        }
    }
    (order.len() >= 2).then_some(MemberPoolPlan { seq_of, order })
}

/// Decode + verify one pooled member on a worker. Mirrors the serial
/// buffered branch of `write_file_to` for a non-solid member: fresh decoder,
/// integrity check, and the LzNoFilters retry against a fresh checkpoint
/// when the filtered output fails verification.
#[cfg(feature = "parallel")]
fn decode_pooled_member(
    archive: &Archive,
    file: &FileHeader,
    password: Option<&[u8]>,
    max_window: u64,
) -> Result<Vec<u8>> {
    let fresh_decoder = || {
        let mut decoder = Unpack50Decoder::new();
        decoder.set_window_limit(usize::try_from(max_window).unwrap_or(usize::MAX));
        decoder.set_retain_history(false);
        decoder
    };
    let mut decoder = fresh_decoder();
    let decoded = file
        .decoded_data_with_decoder(archive, &mut decoder, password)
        .map_err(|error| file.entry_error("decoding", error))?;
    match file.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref()) {
        Ok(()) => Ok(decoded.data),
        Err(filtered_error) => {
            let mut unfiltered_decoder = fresh_decoder();
            let unfiltered = file
                .decoded_data_with_mode(
                    archive,
                    &mut unfiltered_decoder,
                    password,
                    DecodeMode::LzNoFilters,
                )
                .map_err(|error| file.entry_error("decoding", error))?;
            file.verify_integrity_with_keys(&unfiltered.data, unfiltered.keys.as_ref())
                .map_err(|_| file.entry_error("verifying", filtered_error))?;
            Ok(unfiltered.data)
        }
    }
}

#[cfg(feature = "parallel")]
fn extract_volumes_pooled<F, R>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: &mut F,
    redirect: &mut R,
    emit_redirections: bool,
    plan: MemberPoolPlan,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    use std::collections::BTreeMap;
    use std::sync::mpsc;
    use std::sync::{Arc, Condvar, Mutex};

    let password = options.password;
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let max_window = rar50_max_window(options);
    let workers = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .saturating_sub(1)
        .clamp(1, 8)
        .min(plan.order.len());

    // in-flight budget: (bytes enqueued-or-decoded but not yet written, abort)
    let budget = Arc::new((Mutex::new((0u64, false)), Condvar::new()));
    // feeder -> workers; small buffer, the budget is the real regulator
    let (work_tx, work_rx) = mpsc::sync_channel::<usize>(workers * 2);
    let work_rx = Arc::new(Mutex::new(work_rx));
    // workers -> coordinator
    let (result_tx, result_rx) = mpsc::channel::<(usize, Result<Vec<u8>>)>();

    let outcome = std::thread::scope(|scope| {
        // Feeder: pushes pool sequence numbers in archive order, blocking
        // while the in-flight byte budget is full. A single member larger
        // than the whole budget is still admitted alone (in_flight > 0
        // condition) so progress is always possible.
        {
            let budget = Arc::clone(&budget);
            let order = &plan.order;
            let work_tx = work_tx;
            scope.spawn(move || {
                for (seq, entry) in order.iter().enumerate() {
                    let size = entry.unpacked_size;
                    let (lock, cvar) = &*budget;
                    let mut state = lock.lock().expect("pool budget lock");
                    while !state.1 && state.0 > 0 && state.0 + size > POOL_INFLIGHT_BUDGET {
                        state = cvar.wait(state).expect("pool budget wait");
                    }
                    if state.1 {
                        return; // coordinator aborted
                    }
                    state.0 += size;
                    drop(state);
                    if work_tx.send(seq).is_err() {
                        return; // workers gone (coordinator returned early)
                    }
                }
            });
        }

        // Workers: decode + verify, results rejoin the coordinator. A panic
        // inside decode surfaces as an error result instead of deadlocking
        // the coordinator's recv.
        for _ in 0..workers {
            let work_rx = Arc::clone(&work_rx);
            let result_tx = result_tx.clone();
            let order = &plan.order;
            scope.spawn(move || loop {
                let seq = match work_rx.lock().expect("pool work lock").recv() {
                    Ok(seq) => seq,
                    Err(_) => return,
                };
                let entry = &order[seq];
                let archive = &volumes[entry.volume_index];
                let file = entry.file;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decode_pooled_member(archive, file, password, max_window)
                }))
                .unwrap_or(Err(Error::InvalidHeader(
                    "RAR 5 member decode worker panicked",
                )));
                if result_tx.send((seq, result)).is_err() {
                    return; // coordinator gone
                }
            });
        }
        drop(result_tx);

        // Coordinator: the exact serial walk, with pooled members' bytes
        // pulled from the reorder map instead of decoded inline. Inline
        // members (stored, streaming/MT, splits) use the session as today.
        let mut pending: BTreeMap<usize, Result<Vec<u8>>> = BTreeMap::new();
        let mut split = SplitVolumeState::new();
        let mut session =
            DecoderSession::new_with_password(password, buffered_decode_limit, max_window);
        let mut run = || -> Result<()> {
            for (volume_index, archive) in volumes.iter().enumerate() {
                for (file_index, file) in archive.files().enumerate() {
                    match split.advance(file.is_split_before(), file.is_split_after()) {
                        SplitVolumeStep::Regular => {
                            if let Some(redirection) = &file.redirection {
                                if emit_redirections {
                                    redirect(&file.metadata(), redirection)?;
                                }
                                continue;
                            }
                            let meta = file.metadata();
                            if let Some(&seq) = plan.seq_of.get(&(volume_index, file_index)) {
                                let result = loop {
                                    if let Some(result) = pending.remove(&seq) {
                                        break result;
                                    }
                                    match result_rx.recv() {
                                        Ok((got, result)) if got == seq => break result,
                                        Ok((got, result)) => {
                                            pending.insert(got, result);
                                        }
                                        Err(_) => {
                                            return Err(Error::InvalidHeader(
                                                "RAR 5 member decode pool disconnected",
                                            ));
                                        }
                                    }
                                };
                                let data = result?;
                                let mut writer = open(&meta)?;
                                writer
                                    .write_all(&data)
                                    .map_err(Error::from)
                                    .map_err(|error| file.entry_error("writing", error))?;
                                drop(writer);
                                let (lock, cvar) = &*budget;
                                let mut state = lock.lock().expect("pool budget lock");
                                // Credit exactly what the feeder charged, which is the
                                // declared size, not the decoded one: a member may
                                // legitimately decode short (a truncated payload with no
                                // integrity record yields no bytes at all), and crediting
                                // the shorter length would leak the difference until the
                                // feeder parked forever on a budget that never drains.
                                state.0 = state.0.saturating_sub(plan.order[seq].unpacked_size);
                                drop(state);
                                cvar.notify_all();
                            } else {
                                let mut writer = open(&meta)?;
                                if !meta.is_directory {
                                    session.write_file_to(archive, file, &mut writer)?;
                                }
                            }
                        }
                        SplitVolumeStep::Start => {
                            validate_split_fragment(file, password)?;
                            split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                        }
                        SplitVolumeStep::Continue(current) => {
                            validate_split_continuation_refs(current, file, password)?;
                            current.append(volume_index, file_index);
                        }
                        SplitVolumeStep::Finish(mut completed) => {
                            validate_split_continuation_refs(&completed, file, password)?;
                            completed.append(volume_index, file_index);
                            completed.write_to(volumes, file, &mut session, &mut *open)?;
                        }
                        SplitVolumeStep::MissingFirst => {
                            return Err(Error::InvalidHeader(
                                "RAR 5 split entry is missing its first part",
                            ));
                        }
                        SplitVolumeStep::Interrupted => {
                            return Err(Error::InvalidHeader(
                                "RAR 5 split entry is interrupted by a regular entry",
                            ));
                        }
                    }
                }
            }
            if split.is_pending() {
                return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
            }
            Ok(())
        };
        let outcome = run();
        // Wake the feeder out of any budget wait and let every thread drain;
        // dropping result_rx (on scope exit) unblocks workers mid-send.
        let (lock, cvar) = &*budget;
        lock.lock().expect("pool budget lock").1 = true;
        cvar.notify_all();
        outcome
    });
    outcome
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 5 split directory entry is invalid",
        ));
    }
    if file.encrypted && password.is_none() && file.crypto.is_none() {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

fn validate_split_continuation_refs(
    pending: &PendingSplitRefs,
    file: &FileHeader,
    password: Option<&[u8]>,
) -> Result<()> {
    validate_split_fragment(file, password)?;
    if file.name != pending.name {
        return Err(Error::InvalidHeader("RAR 5 split entry name changed"));
    }
    if file.compression_info != pending.compression_info {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry compression info changed",
        ));
    }
    if file.encrypted != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry encryption flag changed",
        ));
    }
    Ok(())
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u64,
    host_os: u64,
    compression_info: u64,
    encrypted: bool,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.mtime.unwrap_or(0),
            attr: file.attributes,
            host_os: file.host_os,
            compression_info: file.compression_info,
            encrypted: file.encrypted,
        }
    }

    fn append(&mut self, volume_index: usize, file_index: usize) {
        self.fragments.push((volume_index, file_index));
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_file: &FileHeader,
        session: &mut DecoderSession<'_>,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let decryptor = session.split_decryptor(&self, volumes)?;
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        if final_file.is_stored() {
            return self
                .write_stored_to(volumes, final_file, decryptor.as_ref(), &mut writer)
                .map_err(|error| final_file.entry_error("extracting", error));
        }

        // Stream large split members through the same pipelined decoder as
        // single-volume files (checksums verified in stream, no whole-member
        // buffer). Pathological filters bail to the buffered path below,
        // mirroring write_file_to.
        if final_file.should_stream_decode(session.buffered_decode_limit) {
            let solid = final_file
                .decoded_compression_info()
                .map_err(|error| final_file.entry_error("decoding", error))?
                .solid;
            let keys = decryptor.as_ref().map(|decryptor| &decryptor.keys);
            let mut reader = self
                .fragment_reader(volumes, decryptor.as_ref())
                .map_err(|error| final_file.entry_error("reading", error))?;
            let mut counting = CountingWriter {
                inner: &mut *writer,
                written: 0,
            };
            let stream_result = if solid {
                // Work on a clone so a failed stream leaves the session's
                // decoder (and its solid history) untouched for the retry.
                let mut streaming_decoder = session.decoder.clone();
                let result = final_file.stream_packed_with_decoder(
                    &mut reader,
                    keys,
                    &mut streaming_decoder,
                    session.buffered_decode_limit,
                    &mut counting,
                );
                if result.is_ok() {
                    session.decoder = streaming_decoder;
                }
                result
            } else {
                final_file.stream_packed_with_decoder(
                    &mut reader,
                    keys,
                    &mut session.decoder,
                    session.buffered_decode_limit,
                    &mut counting,
                )
            };
            match stream_result {
                Ok(()) => return Ok(()),
                Err(error)
                    if counting.written == 0
                        && final_file.unpacked_size <= session.buffered_decode_limit
                        && is_streaming_filter_bail(&error) =>
                {
                    // Buffered retry below; a non-solid member must not see
                    // state the failed stream may have left behind.
                    if !solid {
                        session.decoder = Unpack50Decoder::new();
                    }
                }
                Err(error) => return Err(final_file.entry_error("decoding", error)),
            }
        }

        let data = session
            .decode_split(volumes, &self, final_file, decryptor.as_ref())
            .map_err(|error| final_file.entry_error("decoding", error))?;
        final_file
            .verify_integrity_with_keys(&data, decryptor.as_ref().map(|decryptor| &decryptor.keys))
            .map_err(|error| final_file.entry_error("verifying", error))?;
        writer
            .write_all(&data)
            .map_err(Error::from)
            .map_err(|error| final_file.entry_error("writing", error))?;
        Ok(())
    }

    fn write_stored_to(
        &self,
        volumes: &[Archive],
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let mut reader = self.fragment_reader(volumes, decryptor)?;
        let mut crc = Crc32::new();
        let mut hash = streaming_hash_verifier(final_file)?;
        let mut written = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let count = reader.read(&mut buf)?;
            if count == 0 {
                break;
            }
            let chunk = if final_file.encrypted {
                let remaining = usize::try_from(final_file.unpacked_size.saturating_sub(written))
                    .unwrap_or(usize::MAX);
                let chunk_len = count.min(remaining);
                if buf[chunk_len..count].iter().any(|&byte| byte != 0) {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored split file has non-zero padding",
                    ));
                }
                &buf[..chunk_len]
            } else {
                &buf[..count]
            };
            written = written
                .checked_add(chunk.len() as u64)
                .ok_or(Error::InvalidHeader("RAR 5 stored split size overflows"))?;
            crc.update(chunk);
            if let Some((_, hasher)) = &mut hash {
                hasher.update(chunk);
            }
            writer.write_all(chunk)?;
        }

        if written != final_file.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 stored split file has mismatched packed and unpacked sizes",
            ));
        }
        // Checksums are MAC-converted only when the encryption record's
        // 0x0002 flag says so (`uses_hash_mac`) - `encrypted` alone is the
        // wrong test: header-encrypted (-hp) members are encrypted but
        // store PLAIN checksums unless the flag is set, and MACing them
        // anyway failed verification on byte-perfect output. Mirrors
        // verify_streaming_integrity / verify_integrity_with_keys.
        if let Some(expected) = final_file.data_crc32 {
            let actual = if final_file.uses_hash_mac() {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split CRC needs encryption keys",
                ))?;
                decryptor.keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }
        if let Some((expected, hasher)) = hash {
            let actual = if final_file.uses_hash_mac() {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split hash needs encryption keys",
                ))?;
                decryptor.keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if !constant_time_eq(&expected, &actual) {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    fn split_decryptor(
        &self,
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Option<SplitDecryptor>> {
        if !self.encrypted {
            return Ok(None);
        }
        let (volume_index, file_index) = self.fragments[0];
        let archive = volumes
            .get(volume_index)
            .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
        let file = archive
            .files()
            .nth(file_index)
            .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
        let keys = file
            .crypto_with_password(password)?
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted split file is missing encryption keys",
            ))?;
        Ok(Some(SplitDecryptor {
            keys,
            iv: file.encryption_iv()?,
        }))
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        for &(volume_index, file_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
            readers.push(archive.range_reader(file.block.data_range.clone())?);
        }
        let chained = ChainedReader::new(readers);
        if let Some(decryptor) = decryptor {
            Ok(Box::new(Rar50DecryptingReader::new(
                chained,
                decryptor.keys.key,
                decryptor.iv,
            )))
        } else {
            Ok(Box::new(chained))
        }
    }
}

struct SplitDecryptor {
    keys: Rar50Keys,
    iv: [u8; 16],
}

fn streaming_hash_verifier(file: &FileHeader) -> Result<Option<([u8; 32], blake2sp::Hasher)>> {
    let Some(hash) = &file.hash else {
        return Ok(None);
    };
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&hash.data);
            Ok(Some((expected, blake2sp::Hasher::new())))
        }
        0 => Err(Error::InvalidHeader(
            "RAR 5 BLAKE2sp hash record has invalid length",
        )),
        _ => Ok(None),
    }
}

fn checked_unpacked_size(size: u64) -> Result<usize> {
    usize::try_from(size)
        .map_err(|_| Error::InvalidHeader("RAR 5 unpacked size overflows host address size"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

impl FileHeader {
    fn decode_split_with_decoder(
        &self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        decoder: &mut Unpack50Decoder,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            let mut data = Vec::new();
            let mut reader = split.fragment_reader(volumes, decryptor)?;
            reader.read_to_end(&mut data)?;
            if data.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored split file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(data);
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let mut reader = split.fragment_reader(volumes, decryptor)?;
        let output_size = checked_unpacked_size(self.unpacked_size)?;
        decoder
            .decode_member_from_reader_with_dictionary(
                &mut reader,
                info.algorithm_version,
                output_size,
                dictionary_size,
                info.solid,
                DecodeMode::Lz,
            )
            .map_err(Error::from)
    }
}

struct Rar50DecryptingReader<R> {
    inner: R,
    cipher: Rar50Cipher,
    // Whole-block window: reading and decrypting 16 bytes at a time costs a
    // syscall plus a cipher dispatch per AES block; this batches both.
    buffer: Vec<u8>,
    pos: usize,
    len: usize,
}

const DECRYPT_WINDOW_BYTES: usize = 64 * 1024;

impl<R: Read> Rar50DecryptingReader<R> {
    fn new(inner: R, key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            inner,
            cipher: Rar50Cipher::new(key, iv),
            buffer: vec![0; DECRYPT_WINDOW_BYTES],
            pos: 0,
            len: 0,
        }
    }

    fn fill_buffer(&mut self) -> std::io::Result<bool> {
        let mut read = 0;
        while read < self.buffer.len() {
            let count = self.inner.read(&mut self.buffer[read..])?;
            if count == 0 {
                break;
            }
            read += count;
        }
        if read == 0 {
            return Ok(false);
        }
        if !read.is_multiple_of(16) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated RAR 5 encrypted stream",
            ));
        }
        self.cipher
            .decrypt_in_place(&mut self.buffer[..read])
            .map_err(super::map_rar50_crypto_error)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        self.pos = 0;
        self.len = read;
        Ok(true)
    }
}

impl<R: Read> Read for Rar50DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos == self.len && !self.fill_buffer()? {
            return Ok(0);
        }
        let count = out.len().min(self.len - self.pos);
        out[..count].copy_from_slice(&self.buffer[self.pos..self.pos + count]);
        self.pos += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, CompressedEntry, FileEncryption, FileHash, FilterKind,
        FilterPolicy, MainHeader, Rar50Writer, WriterOptions, HEAD_FILE, HFL_SPLIT_AFTER,
        HFL_SPLIT_BEFORE,
    };
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;
    use std::sync::Arc;

    fn plain_file(name: &[u8], data: &[u8], hash: Option<FileHash>) -> FileHeader {
        FileHeader {
            block: empty_block(HEAD_FILE, 0, 0..0),
            file_flags: 0,
            unpacked_size: data.len() as u64,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: name.to_vec(),
            hash,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        }
    }

    #[test]
    fn decrypting_reader_streams_rar50_blocks() {
        let key = [3u8; 32];
        let iv = [4u8; 16];
        let plain = *b"0123456789abcdefRAR5 block two!!";
        let mut encrypted = plain;
        Rar50Cipher::new(key, iv)
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let mut reader = Rar50DecryptingReader::new(Cursor::new(encrypted), key, iv);
        let mut out = Vec::new();
        let mut buf = [0u8; 5];

        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }

        assert_eq!(out, plain);
    }

    #[test]
    fn stored_split_entries_stream_fragments_to_writer() {
        struct SharedWriter(Rc<RefCell<Vec<u8>>>);

        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let first = b"stored ";
        let second = b"split payload";
        let full = [first.as_slice(), second.as_slice()].concat();
        let expected_crc = crc32(&full);
        let volumes = vec![
            stored_split_archive(first, &full, expected_crc, HFL_SPLIT_AFTER),
            stored_split_archive(second, &full, expected_crc, HFL_SPLIT_BEFORE),
        ];
        let captured = Rc::new(RefCell::new(Vec::new()));
        let sink = captured.clone();

        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            move |_meta| Ok(Box::new(SharedWriter(sink.clone()))),
        )
        .unwrap();

        assert_eq!(&*captured.borrow(), &full);
    }

    #[test]
    fn bounded_filtered_members_use_buffered_decode() {
        let mut data = Vec::new();
        while data.len() + 29 <= BUFFERED_DECODE_LIMIT as usize {
            data.extend_from_slice(b"\xe8\0\0\0\0filtered payload block\n");
        }
        assert!(data.len() as u64 <= BUFFERED_DECODE_LIMIT);

        let archive = Rar50Writer::new(WriterOptions {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
        })
        .compressed_entries(&[CompressedEntry {
            name: b"filtered.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }])
        .filter_policy(FilterPolicy::Explicit(FilterKind::E8))
        .finish()
        .unwrap();
        let archive = Archive::parse(&archive).unwrap();
        let file = archive.files().next().unwrap();
        assert!(!file.should_stream_decode(BUFFERED_DECODE_LIMIT));

        let mut out = Vec::new();
        file.write_to(&archive, None, &mut out).unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn streaming_filtered_members_extract_in_stream() {
        let mut data = Vec::new();
        while data.len() as u64 <= BUFFERED_DECODE_LIMIT {
            data.extend_from_slice(b"\xe8\0\0\0\0filtered payload block\n");
        }

        let archive = Rar50Writer::new(WriterOptions {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
        })
        .compressed_entries(&[CompressedEntry {
            name: b"filtered.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }])
        .filter_policy(FilterPolicy::Explicit(FilterKind::E8))
        .finish()
        .unwrap();
        let archive = Archive::parse(&archive).unwrap();
        let file = archive.files().next().unwrap();
        assert!(file.should_stream_decode(BUFFERED_DECODE_LIMIT));

        let mut out = Vec::new();
        file.write_to(&archive, None, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn streaming_crc32_zero_advance_matches_byte_update() {
        let mut bytewise = Crc32::new();
        bytewise.update(&vec![0; 100_000]);

        let mut skipped = Crc32::new();
        skipped.update_zeroes(100_000);

        assert_eq!(skipped.finish(), bytewise.finish());
    }

    #[test]
    fn repeated_chunk_does_not_advance_crc_after_sink_error() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = FailingWriter;
        let mut crc = Crc32::new();
        let expected = Crc32::new().finish();

        assert!(write_repeated_chunk(&mut writer, &mut crc, &mut None, 0, 1024).is_err());
        assert_eq!(crc.finish(), expected);
    }

    #[test]
    fn encrypted_stored_decode_rejects_nonzero_discarded_padding() {
        let mut file = plain_file(b"secret.txt", b"secret", None);
        file.encrypted = true;
        file.unpacked_size = 6;
        let mut decoder = Unpack50Decoder::new();

        assert_eq!(
            file.decode_packed_with_decoder(b"secret\0\0", &mut decoder)
                .unwrap(),
            b"secret"
        );
        assert!(matches!(
            file.decode_packed_with_decoder(b"secret\0\x01", &mut decoder),
            Err(Error::InvalidHeader(
                "RAR 5 encrypted stored file has non-zero padding"
            ))
        ));
    }

    #[test]
    fn checked_unpacked_size_rejects_values_above_host_usize() {
        assert_eq!(checked_unpacked_size(123).unwrap(), 123usize);

        let overflowing = usize::MAX as u128 + 1;
        if overflowing <= u64::MAX as u128 {
            assert!(checked_unpacked_size(overflowing as u64).is_err());
        }
    }

    #[test]
    fn constant_time_hash_comparison_keeps_hash_validation_behaviour() {
        let data = b"hash me";
        let file = FileHeader {
            block: empty_block(HEAD_FILE, 0, 0..0),
            file_flags: 0,
            unpacked_size: data.len() as u64,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: b"hash.txt".to_vec(),
            hash: Some(FileHash {
                hash_type: 0,
                data: blake2sp::hash(data).to_vec(),
            }),
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        };

        file.verify_integrity_with_keys(data, None).unwrap();

        let mut wrong = file;
        wrong.hash.as_mut().unwrap().data[31] ^= 0x01;
        assert!(matches!(
            wrong.verify_integrity_with_keys(data, None),
            Err(Error::HashMismatch { hash_type: 0 })
        ));
    }

    #[test]
    fn verify_integrity_rejects_bad_blake2sp_length_and_ignores_unknown_hash_type() {
        let data = b"hash me";
        let mut bad_length = plain_file(
            b"a.txt",
            data,
            Some(FileHash {
                hash_type: 0,
                data: vec![0u8; 16],
            }),
        );
        assert!(matches!(
            bad_length.verify_integrity_with_keys(data, None),
            Err(Error::InvalidHeader(_))
        ));

        bad_length.hash.as_mut().unwrap().hash_type = 99;
        bad_length.hash.as_mut().unwrap().data = vec![0u8; 32];
        bad_length.verify_integrity_with_keys(data, None).unwrap();
    }

    #[test]
    fn streaming_hash_verifier_rejects_bad_blake2sp_length_and_ignores_unknown_hash_type() {
        let mut file = plain_file(
            b"a.txt",
            b"",
            Some(FileHash {
                hash_type: 0,
                data: vec![0u8; 16],
            }),
        );
        assert!(matches!(
            streaming_hash_verifier(&file),
            Err(Error::InvalidHeader(_))
        ));

        file.hash.as_mut().unwrap().hash_type = 7;
        file.hash.as_mut().unwrap().data = vec![0u8; 32];
        assert!(matches!(streaming_hash_verifier(&file), Ok(None)));

        let nohash = plain_file(b"a.txt", b"", None);
        assert!(matches!(streaming_hash_verifier(&nohash), Ok(None)));
    }

    #[test]
    fn crypto_with_password_short_circuits_for_unencrypted_or_unsupported_versions() {
        let plain = plain_file(b"a.txt", b"", None);
        assert!(plain.crypto_with_password(None).unwrap().is_none());
        assert!(plain.crypto_with_password(Some(b"pw")).unwrap().is_none());

        let mut missing = plain_file(b"a.txt", b"", None);
        missing.encrypted = true;
        assert!(matches!(
            missing.crypto_with_password(None),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            missing.crypto_with_password(Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let mut bad_version = plain_file(b"a.txt", b"", None);
        bad_version.encrypted = true;
        bad_version.encryption = Some(FileEncryption {
            version: 1,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [0u8; 16],
            check_value: None,
        });
        assert!(matches!(
            bad_version.crypto_with_password(Some(b"pw")),
            Err(Error::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn crypto_with_password_handles_missing_check_value() {
        let mut file = plain_file(b"a.txt", b"", None);
        file.encrypted = true;
        file.encryption = Some(FileEncryption {
            version: 0,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [0u8; 16],
            check_value: None,
        });
        assert!(file.crypto_with_password(Some(b"pw")).unwrap().is_some());
    }

    #[test]
    fn decode_packed_rejects_stored_size_mismatch() {
        let mut decoder = Unpack50Decoder::new();

        let mut file = plain_file(b"a.txt", &[0u8; 32], None);
        file.unpacked_size = 32;
        let short = vec![0u8; 16];
        assert!(matches!(
            file.decode_packed_with_decoder(&short, &mut decoder),
            Err(Error::InvalidHeader(_))
        ));

        let mut encrypted = plain_file(b"b.txt", &[0u8; 32], None);
        encrypted.encrypted = true;
        encrypted.unpacked_size = 32;
        let too_short = vec![0u8; 16];
        assert!(matches!(
            encrypted.decode_packed_with_decoder(&too_short, &mut decoder),
            Err(Error::InvalidHeader(_))
        ));

        let exact = vec![0u8; 64];
        let trimmed = encrypted
            .decode_packed_with_decoder(&exact, &mut decoder)
            .unwrap();
        assert_eq!(trimmed.len(), encrypted.unpacked_size as usize);
    }

    #[test]
    fn verify_streaming_integrity_validates_crc_and_hash() {
        let payload = b"streaming";
        let crc_value = crc32(payload);
        let hash_value = blake2sp::hash(payload);

        let mut file = plain_file(b"s.txt", payload, None);
        file.data_crc32 = Some(crc_value);
        file.hash = Some(FileHash {
            hash_type: 0,
            data: hash_value.to_vec(),
        });

        let make_state = || {
            let mut crc = Crc32::new();
            crc.update(payload);
            let mut hasher = blake2sp::Hasher::new();
            hasher.update(payload);
            (crc, Some((hash_value, hasher)))
        };

        let (crc, hash) = make_state();
        file.verify_streaming_integrity(crc, hash, None).unwrap();

        let (crc, hash) = make_state();
        let mut bad = file.clone();
        bad.data_crc32 = Some(crc_value ^ 0x1);
        assert!(matches!(
            bad.verify_streaming_integrity(crc, hash, None),
            Err(Error::Crc32Mismatch { .. })
        ));

        let (crc, _) = make_state();
        let mut wrong_expected = hash_value;
        wrong_expected[0] ^= 0xff;
        let mut hasher = blake2sp::Hasher::new();
        hasher.update(payload);
        let mut bad_hash = file.clone();
        bad_hash.data_crc32 = None;
        assert!(matches!(
            bad_hash.verify_streaming_integrity(crc, Some((wrong_expected, hasher)), None),
            Err(Error::HashMismatch { hash_type: 0 })
        ));

        let empty = plain_file(b"e.txt", b"", None);
        empty
            .verify_streaming_integrity(Crc32::new(), None, None)
            .unwrap();
    }

    #[test]
    fn write_repeated_chunk_updates_crc_hash_and_writer() {
        let mut writer = Vec::new();
        let mut crc_zero = Crc32::new();
        let mut hash = Some(([0u8; 32], blake2sp::Hasher::new()));
        write_repeated_chunk(&mut writer, &mut crc_zero, &mut hash, 0, 70_000).unwrap();
        assert_eq!(writer.len(), 70_000);
        let zero_crc = crc_zero.finish();

        let mut bytewise = Crc32::new();
        bytewise.update(&vec![0u8; 70_000]);
        assert_eq!(zero_crc, bytewise.finish());

        let mut writer = Vec::new();
        let mut crc_ff = Crc32::new();
        let mut hash_none: Option<([u8; 32], blake2sp::Hasher)> = None;
        write_repeated_chunk(&mut writer, &mut crc_ff, &mut hash_none, 0xff, 1024).unwrap();
        assert_eq!(writer, vec![0xffu8; 1024]);
    }

    #[test]
    fn map_rar50_crypto_error_translates_kdf_count() {
        assert!(matches!(
            super::super::map_rar50_crypto_error(crate::crypto::rar50::Error::KdfCountTooLarge),
            Error::UnsupportedFeature { .. }
        ));
        assert!(matches!(
            super::super::map_rar50_crypto_error(crate::crypto::rar50::Error::BadPassword),
            Error::WrongPasswordOrCorruptData
        ));
    }

    #[test]
    fn constant_time_eq_returns_false_for_length_mismatch() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    fn stored_split_archive(data: &[u8], full: &[u8], crc: u32, flags: u64) -> Archive {
        let source: Arc<[u8]> = Arc::from(data.to_vec().into_boxed_slice());
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                block: empty_block(1, 0, 0..0),
                archive_flags: 0,
                volume_number: None,
                extras: Vec::new(),
            },
            blocks: vec![Block::File(FileHeader {
                block: empty_block(HEAD_FILE, flags, 0..data.len()),
                file_flags: 0,
                unpacked_size: full.len() as u64,
                attributes: 0x20,
                mtime: None,
                data_crc32: Some(crc),
                compression_info: 0,
                host_os: 2,
                name: b"split.txt".to_vec(),
                hash: Some(FileHash {
                    hash_type: 0,
                    data: blake2sp::hash(full).to_vec(),
                }),
                redirection: None,
                service_data: None,
                encrypted: false,
                encryption: None,
                crypto: None,
            })],
            source: ArchiveSource::Memory(source),
        }
    }

    fn empty_block(
        header_type: u64,
        flags: u64,
        data_range: std::ops::Range<usize>,
    ) -> BlockHeader {
        BlockHeader {
            header_crc: 0,
            header_size: 0,
            header_type,
            flags,
            extra_area_size: None,
            data_size: Some(data_range.len() as u64),
            offset: 0,
            header_range: 0..0,
            data_range,
        }
    }

    fn split_fragment_file(name: &[u8], hfl_flags: u64) -> FileHeader {
        FileHeader {
            block: empty_block(HEAD_FILE, hfl_flags, 0..0),
            file_flags: 0,
            unpacked_size: 0,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: name.to_vec(),
            hash: None,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        }
    }

    fn archive_with_blocks(blocks: Vec<Block>, source: Vec<u8>) -> Archive {
        let bytes: Arc<[u8]> = Arc::from(source.into_boxed_slice());
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                block: empty_block(1, 0, 0..0),
                archive_flags: 0,
                volume_number: None,
                extras: Vec::new(),
            },
            blocks,
            source: ArchiveSource::Memory(bytes),
        }
    }

    fn never_open(_meta: &ExtractedEntryMeta) -> Result<Box<dyn Write>> {
        panic!("open should not be invoked for this test");
    }

    #[test]
    fn extract_volumes_to_rejects_volume_state_violations() {
        let empty: Vec<Archive> = Vec::new();
        assert!(matches!(
            extract_volumes_to(&empty, crate::ArchiveReadOptions::default(), never_open),
            Err(Error::InvalidHeader(_))
        ));

        let only_continuation = vec![archive_with_blocks(
            vec![Block::File(split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE))],
            Vec::new(),
        )];
        assert!(matches!(
            extract_volumes_to(
                &only_continuation,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let interrupted = vec![archive_with_blocks(
            vec![
                Block::File(split_fragment_file(b"a.txt", HFL_SPLIT_AFTER)),
                Block::File(plain_file(b"other.txt", b"", None)),
            ],
            Vec::new(),
        )];
        assert!(matches!(
            extract_volumes_to(
                &interrupted,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let incomplete = vec![archive_with_blocks(
            vec![Block::File(split_fragment_file(b"a.txt", HFL_SPLIT_AFTER))],
            Vec::new(),
        )];
        assert!(matches!(
            extract_volumes_to(
                &incomplete,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn validate_split_fragment_rejects_directories_and_demands_password_for_encrypted() {
        let mut dir = split_fragment_file(b"d", HFL_SPLIT_AFTER);
        dir.file_flags = 0x0001;
        assert!(matches!(
            validate_split_fragment(&dir, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut encrypted = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        encrypted.encrypted = true;
        assert!(matches!(
            validate_split_fragment(&encrypted, None),
            Err(Error::NeedPassword)
        ));
        validate_split_fragment(&encrypted, Some(b"pw")).unwrap();

        let plain = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        validate_split_fragment(&plain, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_property_drift_between_fragments() {
        let first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let renamed = split_fragment_file(b"b.txt", HFL_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &renamed, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_compression = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        new_compression.compression_info = 0x123;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_compression, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_encryption = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        new_encryption.encrypted = true;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_encryption, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let same = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        validate_split_continuation_refs(&pending, &same, None).unwrap();
    }

    #[test]
    fn archive_extract_to_rejects_split_entries_in_single_volume_archive() {
        let split = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        let archive = archive_with_blocks(vec![Block::File(split)], Vec::new());
        let err = archive
            .extract_to(crate::ArchiveReadOptions::default(), never_open)
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("requires multivolume")),
            "expected multivolume error, got {err:?}"
        );
    }

    #[test]
    fn archive_extract_to_skips_redirection_entries_without_opening_writer() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 1,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let archive = archive_with_blocks(vec![Block::File(redirect)], Vec::new());
        archive
            .extract_to(crate::ArchiveReadOptions::default(), never_open)
            .unwrap();
    }

    #[test]
    fn archive_extract_to_with_redirections_reports_redirection_entries() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 1,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let archive = archive_with_blocks(vec![Block::File(redirect)], Vec::new());
        let mut seen = Vec::new();
        archive
            .extract_to_with_redirections(
                crate::ArchiveReadOptions::default(),
                never_open,
                |meta, redirection| {
                    seen.push((meta.name.clone(), redirection.target_name.clone()));
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(seen, vec![(b"link".to_vec(), b"target".to_vec())]);
    }

    #[test]
    fn extract_volumes_to_skips_redirection_entries_without_opening_writer() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 1,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let volumes = vec![archive_with_blocks(vec![Block::File(redirect)], Vec::new())];
        extract_volumes_to(&volumes, crate::ArchiveReadOptions::default(), never_open).unwrap();
    }

    #[test]
    fn extract_volumes_to_with_redirections_reports_redirection_entries() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 5,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let volumes = vec![archive_with_blocks(vec![Block::File(redirect)], Vec::new())];
        let mut seen = Vec::new();
        extract_volumes_to_with_redirections(
            &volumes,
            crate::ArchiveReadOptions::default(),
            never_open,
            |meta, redirection| {
                seen.push((meta.name.clone(), redirection.target_name.clone()));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(seen, vec![(b"link".to_vec(), b"target".to_vec())]);
    }

    /// A member the decode pool accepts: v0 algorithm, non-solid, method 3,
    /// no CRC32 and no hash. It carries no packed bytes at all, so its decode
    /// ends short and the missing integrity record turns that into an empty
    /// payload instead of an error.
    #[cfg(feature = "parallel")]
    fn truncated_pooled_file(name: &[u8], unpacked_size: u64) -> FileHeader {
        let mut file = plain_file(name, b"", None);
        file.compression_info = 0x180;
        file.unpacked_size = unpacked_size;
        file
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn pooled_members_that_decode_short_still_release_their_budget() {
        // Enough members to charge the whole in-flight budget and one more,
        // every one of them decoding to nothing. Crediting the decoded length
        // rather than the charged size leaves the budget full forever, so the
        // feeder parks and the extraction never finishes.
        let member = BUFFERED_DECODE_LIMIT;
        let count = (POOL_INFLIGHT_BUDGET / member + 1) as usize;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let blocks = (0..count)
                .map(|index| {
                    Block::File(truncated_pooled_file(
                        format!("m{index}.bin").as_bytes(),
                        member,
                    ))
                })
                .collect();
            let volumes = vec![archive_with_blocks(blocks, Vec::new())];
            let mut opened = 0usize;
            let outcome = extract_volumes_to(
                &volumes,
                crate::ArchiveReadOptions::default(),
                |_meta| -> Result<Box<dyn Write>> {
                    opened += 1;
                    Ok(Box::new(Vec::new()))
                },
            );
            let _ = done_tx.send(outcome.map(|()| opened).map_err(|error| error.to_string()));
        });

        assert_eq!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("pooled extraction deadlocked"),
            Ok(count)
        );
    }

    #[test]
    fn stream_packed_with_decoder_rejects_stored_files() {
        let file = plain_file(b"stored.txt", b"hello", None);
        assert!(file.is_stored());
        let mut decoder = Unpack50Decoder::new();
        let mut out: Vec<u8> = Vec::new();
        let err = file
            .stream_packed_with_decoder(
                &mut Cursor::new(Vec::<u8>::new()),
                None,
                &mut decoder,
                BUFFERED_DECODE_LIMIT,
                &mut out,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("does not use streaming")),
            "expected streaming-rejection error, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_unpacked_size_mismatch() {
        let payload: &[u8] = b"unmatched-size payload";
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = (payload.len() + 5) as u64; // mismatch
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out)
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("mismatched packed and unpacked")),
            "expected size mismatch error, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_crc_mismatch_on_unencrypted() {
        let payload: &[u8] = b"crc-mismatch payload";
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = payload.len() as u64;
        first.data_crc32 = Some(crc32(payload).wrapping_add(1));
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out)
            .unwrap_err();
        assert!(
            matches!(err, Error::Crc32Mismatch { .. }),
            "expected CRC mismatch, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_hash_mismatch_on_unencrypted() {
        let payload: &[u8] = b"hash-mismatch payload";
        let mut wrong_hash = blake2sp::hash(payload);
        wrong_hash[0] ^= 0xff;

        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = payload.len() as u64;
        first.data_crc32 = Some(crc32(payload));
        first.hash = Some(FileHash {
            hash_type: 0,
            data: wrong_hash.to_vec(),
        });
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out)
            .unwrap_err();
        assert!(
            matches!(err, Error::HashMismatch { hash_type: 0 }),
            "expected hash mismatch, got {err:?}"
        );
    }

    #[test]
    fn decoded_data_with_mode_dispatches_through_decode_packed_for_stored_files() {
        let payload = b"decoded_data_with_mode stored payload";
        let mut file = plain_file(b"a.txt", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let mut decoder = Unpack50Decoder::new();
        let decoded = file
            .decoded_data_with_mode(&archive, &mut decoder, None, DecodeMode::Lz)
            .unwrap();
        assert_eq!(decoded.data, payload);
        assert!(decoded.keys.is_none());

        // LzNoFilters dispatches through the same stored short-circuit.
        let mut decoder = Unpack50Decoder::new();
        let decoded = file
            .decoded_data_with_mode(&archive, &mut decoder, None, DecodeMode::LzNoFilters)
            .unwrap();
        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn decoded_data_unverified_returns_stored_payload_without_crc_check() {
        let payload = b"decoded_data_unverified stored payload";
        let mut file = plain_file(b"a.txt", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;
        // Set wrong CRC — unverified path must not check it.
        file.data_crc32 = Some(crc32(payload).wrapping_add(1));

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let decoded = file.decoded_data_unverified(&archive, None).unwrap();
        assert_eq!(decoded, payload);
    }

    /// The unverified decode sizes its output from a header field the archive
    /// author picks, and consults neither the buffered-decode limit nor the
    /// window limit that ordinary extraction applies. A member that is tiny on
    /// the wire but claims gigabytes therefore decodes until the allocation
    /// fails, which in Rust is an abort - and for a service record that
    /// happens automatically, before any content check.
    #[test]
    fn decoded_data_unverified_bounded_refuses_an_oversized_declared_size() {
        let payload = b"tiny on the wire, enormous in the header";
        let mut file = plain_file(b"RR", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = 8 * 1024 * 1024 * 1024; // 8 GiB claimed

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let err = file
            .decoded_data_unverified_bounded(&archive, None, payload.len() as u64)
            .unwrap_err();
        assert!(
            matches!(err, Error::Rar50BufferedDecodeLimitExceeded { .. }),
            "expected a bounded refusal, got {err:?}"
        );
    }

    /// An archive whose `RR` service is COMPRESSED, which is the branch a
    /// stored recovery record never reaches.
    ///
    /// The prefix is real bytes; the service declares `declared_unpacked` as
    /// its output. Nothing here has to decode successfully - the property
    /// under test is which ceiling gets applied before the decode is even
    /// attempted.
    fn archive_with_compressed_rr(prefix_len: usize, declared_unpacked: u64) -> (Archive, usize) {
        let mut source = vec![0xABu8; prefix_len];
        let packed = vec![0u8; 64];
        let service_offset = source.len();
        source.extend_from_slice(&packed);

        let mut service = plain_file(b"RR", &packed, None);
        // Method 1 (not stored), so `is_stored()` is false and the streaming
        // repair takes its decode branch instead of reading in place.
        service.compression_info = 1 << 7;
        service.unpacked_size = declared_unpacked;
        service.block = empty_block(
            crate::rar50::HEAD_SERVICE,
            0,
            service_offset..service_offset + packed.len(),
        );
        service.block.offset = service_offset;
        // `recovery_record()` wants a single vint percent and nothing after.
        service.service_data = Some(vec![5u8]);

        let total = source.len();
        (
            archive_with_blocks(vec![Block::Service(service)], source),
            total,
        )
    }

    #[test]
    fn streaming_repair_bounds_a_compressed_rr_service_by_the_archive_not_the_budget() {
        // The compressed-RR branch is unreachable from our own writer, which
        // always stores recovery records - so this is the only way to pin the
        // ceiling it applies. Two independent bounds exist: the archive's own
        // length (a recovery record cannot legitimately be larger than the
        // archive carrying it) and the caller's memory budget. Passing only
        // the budget would accept a tiny archive declaring a huge recovery
        // service on any box whose repair slice happens to be wide, which is
        // exactly what the buffered path already refuses.
        let (archive, source_len) = archive_with_compressed_rr(4096, 512 * 1024 * 1024);
        assert!(
            archive
                .services()
                .any(|s| !s.is_stored() && matches!(s.recovery_record(), Ok(Some(_)))),
            "fixture must actually exercise the compressed-RR branch"
        );

        let mut path = std::env::temp_dir();
        path.push(format!("rars-cmpr-rr-{}", std::process::id()));
        let mut dest = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        // A budget far WIDER than the archive: only the archive-size bound can
        // refuse this, so it proves which one is binding.
        let err = archive
            .repair_recovery_to_file(&mut dest, None, u64::MAX)
            .unwrap_err();
        std::fs::remove_file(&path).ok();
        let text = err.to_string();
        assert!(
            text.contains("buffered decode limit") || text.contains("limit"),
            "expected the archive-size ceiling to refuse, got: {text}"
        );
        assert!(
            source_len < 512 * 1024 * 1024,
            "the declared service must exceed the archive for this to mean anything"
        );
    }

    #[test]
    fn streaming_repair_lets_a_compressed_rr_service_inside_both_bounds_through() {
        // The mirror of the test above: a service declaring less than the
        // archive holds must get PAST the ceiling and fail later on the
        // recovery data itself. Without this, a ceiling that refused
        // everything would look identical.
        let (archive, _) = archive_with_compressed_rr(4096, 128);
        let mut path = std::env::temp_dir();
        path.push(format!("rars-cmpr-rr-ok-{}", std::process::id()));
        let mut dest = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let err = archive
            .repair_recovery_to_file(&mut dest, None, u64::MAX)
            .unwrap_err();
        std::fs::remove_file(&path).ok();
        let text = err.to_string();
        assert!(
            !text.contains("buffered decode limit"),
            "a service inside both bounds must not be refused by the ceiling: {text}"
        );
    }

    #[test]
    fn decoded_data_unverified_bounded_refuses_an_oversized_packed_member() {
        // The declared output is not the only allocation: the packed member
        // is buffered WHOLE to produce it, so a member that is small in its
        // header but large on the wire has to be refused on the input side
        // too. Bounding only `unpacked_size` left half of it unchecked.
        let payload = vec![0u8; 4096];
        let mut file = plain_file(b"RR", &payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = 16; // modest claim, large body

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.clone());
        let err = file
            .decoded_data_unverified_bounded(&archive, None, 64)
            .unwrap_err();
        assert!(
            matches!(err, Error::Rar50BufferedDecodeLimitExceeded { .. }),
            "expected a bounded refusal on the packed side, got {err:?}"
        );
    }

    /// ...and the bound must not cost a legitimate record anything.
    #[test]
    fn decoded_data_unverified_bounded_still_decodes_within_the_limit() {
        let payload = b"an honest recovery record";
        let mut file = plain_file(b"RR", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let decoded = file
            .decoded_data_unverified_bounded(&archive, None, payload.len() as u64)
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decoded_data_unverified_accepts_empty_compressed_member() {
        let mut file = plain_file(b"empty.txt", b"", None);
        file.compression_info = 5 << 7;
        file.data_crc32 = Some(0);

        let archive = archive_with_blocks(vec![Block::File(file.clone())], Vec::new());
        let decoded = file.decoded_data_unverified(&archive, None).unwrap();

        assert!(decoded.is_empty());
    }

    #[test]
    fn map_truncated_unverified_payload_swallows_need_more_input_when_no_integrity_record() {
        let mut file = plain_file(b"a.txt", b"", None);
        file.data_crc32 = None;
        file.hash = None;
        assert!(file
            .map_truncated_unverified_payload(crate::codec::Error::NeedMoreInput)
            .unwrap()
            .is_empty());

        file.data_crc32 = Some(0);
        assert!(file
            .map_truncated_unverified_payload(crate::codec::Error::NeedMoreInput)
            .is_err());
    }

    #[test]
    fn encryption_iv_falls_back_to_encryption_record_and_errors_when_missing() {
        let mut with_record = plain_file(b"a.txt", b"", None);
        with_record.encrypted = true;
        with_record.encryption = Some(FileEncryption {
            version: 0,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [5u8; 16],
            check_value: None,
        });
        assert_eq!(with_record.encryption_iv().unwrap(), [5u8; 16]);

        let missing = plain_file(b"a.txt", b"", None);
        assert!(matches!(
            missing.encryption_iv(),
            Err(Error::InvalidHeader(_))
        ));
    }
}

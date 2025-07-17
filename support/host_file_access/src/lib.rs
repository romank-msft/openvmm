// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple transfer protocol with support for seeks.
//!
//! The forward seeks beyond the size of the file might be platform dependendant.
//! Normally, the OS extends the file thus providing a way to truncate the file
//! to the desired size fast.
//!
//! Each transfer starts with the header packetthat provides the seek position,
//! size and the dierction. It might be followed by the data bytes sent in the
//! either direction. The sentinel value of `-1i128` for the header designates the
//! end of the file. Any transfer after that will return an error.
use bitfield_struct::bitfield;
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use open_enum::open_enum;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

open_enum! {
    /// Represents the position from which to seek in the medium.
    #[derive(IntoBytes, FromBytes, Immutable)]
    pub(crate) enum SeekPosition: u8 {
        /// Seek relative to the current position.
        CURRENT = 0b00,
        /// Seek relative to the start of the medium.
        START = 0b01,
        /// Seek relative to the end of the medium.
        END = 0b10,
        /// No seek position specified.
        NONE = 0b11,
    }
}

impl SeekPosition {
    const fn into_bits(self) -> u8 {
        self.0
    }

    const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

open_enum! {
    /// Represents the direction of the data transfer.
    #[derive(IntoBytes, FromBytes, Immutable)]
    pub(crate) enum HostFileOperation: u8 {
        /// Write data to the medium.
        WRITE = 0,
        /// Read data from the medium.
        READ = 1,
        /// Seek operation
        SEEK = 2,
    }
}

impl HostFileOperation {
    const fn into_bits(self) -> u8 {
        self.0
    }

    const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

/// Represents the transport header.
#[derive(IntoBytes, FromBytes, Immutable)]
#[bitfield(u128)]
pub(crate) struct TransportHeader {
    #[bits(2)]
    pub operation: HostFileOperation,
    #[bits(2)]
    pub seek_pos: SeekPosition,
    #[bits(60)]
    _res: u64,
    #[bits(64)]
    pub size: usize,
}

impl TransportHeader {
    /// Checks if the header represents the end of the file.
    pub fn is_eof(&self) -> bool {
        self.into_bits() == Self::eof().into_bits()
    }

    /// Creates the end of file header.
    pub fn eof() -> Self {
        Self::from_bits(-1i128 as u128)
    }

    /// Checks if the header requests flushing the medium.
    pub fn is_flush(&self) -> bool {
        self.into_bits() == Self::flush().into_bits()
    }

    /// Creates a new transport header to request flushing the medium.
    pub fn flush() -> Self {
        Self::from_bits(0)
    }
}

/// Errors that can occur during host data operations.
#[derive(Debug, thiserror::Error)]
pub enum HostFileError {
    /// End of file reached.
    #[error("end of file reached")]
    EndOfFile,
    /// Invalid seek position specified in the header.
    #[error("invalid seek position specified in the header")]
    InvalidSeekPosition,
    /// Invalid data size specified in the header.
    #[error("invalid data size specified in the header")]
    InvalidDataSize,
    /// Write limit exceeded.
    #[error("write limit exceeded")]
    WriteLimitExceeded,
    /// Invalid direction specified in the header.
    #[error("invalid direction specified in the header")]
    InvalidOperation,
    /// An I/O error occurred during the operation.
    #[error("I/O error occurred during the operation")]
    IoError(#[source] std::io::Error),
}

/// Provides input for the host data operations.
pub(crate) enum HostData<'a> {
    /// Data to be written to the medium.
    Write(&'a [u8]),
    /// Buffer to read data into from the medium.
    Read(&'a mut [u8]),
}

/// Represents the write limit for the data storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteLimit {
    /// No write limit.
    None,
    /// A specific write limit in bytes.
    Limit(usize),
}

impl From<Option<usize>> for WriteLimit {
    fn from(limit: Option<usize>) -> Self {
        match limit {
            Some(size) => WriteLimit::Limit(size),
            None => WriteLimit::None,
        }
    }
}

/// A storage medium for the data operations.
pub struct HostFileStorage<'a, M: Read + Write + Seek> {
    medium: &'a mut M,
    write_limit: WriteLimit,
    bytes_read: usize,
    bytes_written: usize,
    eof: bool,
}

impl<'a, M: Read + Write + Seek> HostFileStorage<'a, M> {
    /// Creates a new `HostFileStorage` with the given medium.
    pub fn new(medium: &'a mut M, write_limit: WriteLimit) -> Self {
        Self {
            medium,
            write_limit,
            bytes_read: 0,
            bytes_written: 0,
            eof: false,
        }
    }

    /// Returns the number of bytes read so far.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Returns the number of bytes written so far.
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Performs a data transfer with the given header and data.
    /// Returns the number of bytes transferred, new position or an error if the operation failed.
    pub(crate) fn transfer(
        &mut self,
        header: TransportHeader,
        data: HostData<'_>,
    ) -> Result<usize, HostFileError> {
        if self.eof {
            tracing::info!("Transfer requested after EOF reached");
            return Err(HostFileError::EndOfFile);
        }

        if header.is_eof() {
            tracing::info!("End of file header received");
            self.eof = true;
            return Err(HostFileError::EndOfFile);
        } else if header.is_flush() {
            tracing::info!("Flush header received");
            self.medium.flush().map_err(HostFileError::IoError)?;
            return Ok(0);
        }

        tracing::info!("Transfer header {header:?}");

        match header.operation() {
            HostFileOperation::SEEK => {
                let seek_amount = header.size();
                let seek_from = match header.seek_pos() {
                    SeekPosition::CURRENT => std::io::SeekFrom::Current(seek_amount as i64),
                    SeekPosition::START => std::io::SeekFrom::Start(seek_amount as u64),
                    SeekPosition::END => std::io::SeekFrom::End(seek_amount as i64),
                    _ => return Err(HostFileError::InvalidSeekPosition),
                };

                let offset = self
                    .medium
                    .seek(seek_from)
                    .map_err(HostFileError::IoError)?;
                Ok(offset as usize)
            }
            HostFileOperation::WRITE => {
                if let HostData::Write(bytes_to_write) = data {
                    if bytes_to_write.len() != header.size() {
                        return Err(HostFileError::InvalidDataSize);
                    }
                    if let WriteLimit::Limit(limit) = self.write_limit {
                        if self.bytes_written + header.size() > limit {
                            tracing::info!(
                                "Write limit exceeded: {} bytes written, limit is {} bytes",
                                self.bytes_written,
                                limit
                            );
                            return Err(HostFileError::WriteLimitExceeded);
                        }
                    }

                    self.medium
                        .write_all(bytes_to_write)
                        .map_err(HostFileError::IoError)?;
                    self.bytes_written += bytes_to_write.len();

                    Ok(bytes_to_write.len())
                } else {
                    Err(HostFileError::InvalidOperation)
                }
            }
            HostFileOperation::READ => {
                if let HostData::Read(buffer) = data {
                    if buffer.len() != header.size() {
                        return Err(HostFileError::InvalidDataSize);
                    }

                    let bytes_read = self.medium.read(buffer).map_err(HostFileError::IoError)?;
                    self.bytes_read += bytes_read;

                    Ok(bytes_read)
                } else {
                    Err(HostFileError::InvalidOperation)
                }
            }
            _ => Err(HostFileError::InvalidOperation),
        }
    }

    /// Runs the data operations on the provided transport.
    pub fn run<T: Read + Write>(&mut self, mut transport: T) -> Result<(), HostFileError> {
        if self.eof {
            return Err(HostFileError::EndOfFile);
        }

        loop {
            let mut header = TransportHeader::eof();
            transport
                .read_exact(header.as_mut_bytes())
                .map_err(HostFileError::IoError)?;

            tracing::info!("Received header: {:?}", header);

            if header.is_eof() {
                self.eof = true;
                return Ok(());
            }

            let mut buf = vec![0; header.size()];
            match header.operation() {
                HostFileOperation::SEEK => {
                    let new_pos = self.transfer(header, HostData::Write(&[]))?;
                    transport
                        .write_all(new_pos.as_bytes())
                        .map_err(HostFileError::IoError)?;
                }
                HostFileOperation::READ => {
                    let bytes_read = self.transfer(header, HostData::Read(&mut buf))?;
                    transport
                        .write_all(bytes_read.as_bytes())
                        .map_err(HostFileError::IoError)?;
                    if bytes_read == 0 {
                        tracing::info!("End of file reached during read operation");
                        self.eof = true;
                        return Ok(());
                    }
                    transport
                        .write_all(&buf[..bytes_read])
                        .map_err(HostFileError::IoError)?;
                }
                HostFileOperation::WRITE => {
                    transport
                        .read_exact(&mut buf)
                        .map_err(HostFileError::IoError)?;
                    self.transfer(header, HostData::Write(&buf))?;
                }
                _ => return Err(HostFileError::InvalidOperation),
            }
        }
    }

    /// Runs the data operations on the provided transport.
    pub async fn run_async<T: AsyncReadExt + AsyncWriteExt + Unpin>(
        &mut self,
        mut transport: T,
    ) -> Result<(), HostFileError> {
        if self.eof {
            return Err(HostFileError::EndOfFile);
        }

        let mut header = TransportHeader::eof();
        transport
            .read_exact(header.as_mut_bytes())
            .await
            .map_err(HostFileError::IoError)?;

        tracing::info!("Received header: {:?}", header);

        if header.is_eof() {
            self.eof = true;
            return Ok(());
        }

        let mut buf = vec![0; header.size()];
        match header.operation() {
            HostFileOperation::SEEK => {
                let new_pos = self.transfer(header, HostData::Write(&[]))?;
                transport
                    .write_all(new_pos.as_bytes())
                    .await
                    .map_err(HostFileError::IoError)?;
            }
            HostFileOperation::READ => {
                let bytes_read = self.transfer(header, HostData::Read(&mut buf))?;
                transport
                    .write_all(bytes_read.as_bytes())
                    .await
                    .map_err(HostFileError::IoError)?;
                if bytes_read == 0 {
                    tracing::info!("End of file reached during read operation");
                    self.eof = true;
                    return Ok(());
                }
                transport
                    .write_all(&buf[..bytes_read])
                    .await
                    .map_err(HostFileError::IoError)?;
            }
            HostFileOperation::WRITE => {
                transport
                    .read_exact(&mut buf)
                    .await
                    .map_err(HostFileError::IoError)?;
                self.transfer(header, HostData::Write(&buf))?;
            }
            _ => return Err(HostFileError::InvalidOperation),
        }
        Ok(())
    }
}

/// A wrapper around a transport that provides file-like access.
pub struct HostFileAccess<'a, T: Read + Write> {
    transport: &'a mut T,
    pos: u64,
}

impl<'a, T: Read + Write> HostFileAccess<'a, T> {
    /// Creates a new `HostFileAccess` with the given transport.
    pub fn new(transport: &'a mut T) -> std::io::Result<Self> {
        let mut hfa = Self { transport, pos: 0 };
        hfa.seek(std::io::SeekFrom::Start(0))?;

        Ok(hfa)
    }
}

impl<'a, T: Read + Write> Drop for HostFileAccess<'a, T> {
    fn drop(&mut self) {
        tracing::info!("Dropping HostFileAccess, sending EOF header");
        let header = TransportHeader::eof();
        if let Err(e) = self.transport.write_all(header.as_bytes()) {
            tracing::error!("Failed to write EOF header: {}", e);
        }
    }
}

impl<'a, T: Read + Write> Write for HostFileAccess<'a, T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        tracing::info!("Writing {} bytes to host file access", buf.len());

        let header = TransportHeader::new()
            .with_operation(HostFileOperation::WRITE)
            .with_size(buf.len());

        tracing::info!("Writing header to host file access: {:?}", header);
        self.transport.write_all(header.as_bytes())?;

        tracing::info!("Writing data to host file access");
        self.transport.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        tracing::info!("Flushing host file access");

        let header = TransportHeader::flush();
        self.transport.write_all(header.as_bytes())
    }
}

impl<'a, T: Read + Write> Read for HostFileAccess<'a, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        tracing::info!("Reading {} bytes from host file access", buf.len());

        let header = TransportHeader::new()
            .with_operation(HostFileOperation::READ)
            .with_size(buf.len());

        tracing::info!("Writing header to host file access: {:?}", header);
        self.transport
            .write_all(header.as_bytes())
            .map_err(std::io::Error::other)?;

        tracing::info!("Reading size from host file access");
        let mut size = 0usize;
        self.transport
            .read_exact(size.as_mut_bytes())
            .map_err(std::io::Error::other)?;
        if size == 0 {
            tracing::info!("End of file reached during read operation");
            return Ok(0);
        }

        tracing::info!("Reading data from host file access");
        self.transport.read(buf)
    }
}

impl<'a, T: Read + Write> Seek for HostFileAccess<'a, T> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        tracing::info!("Seeking in host file access to {:?}", pos);

        let (seek_pos, size) = match pos {
            std::io::SeekFrom::Start(offset) => (SeekPosition::START, offset as usize),
            std::io::SeekFrom::End(offset) => (SeekPosition::END, offset as usize),
            std::io::SeekFrom::Current(offset) => (SeekPosition::CURRENT, offset as usize),
        };

        let header = TransportHeader::new()
            .with_operation(HostFileOperation::SEEK)
            .with_seek_pos(seek_pos)
            .with_size(size);

        self.transport
            .write_all(header.as_bytes())
            .map_err(std::io::Error::other)?;

        let mut new_pos = 0u64;
        self.transport.read_exact(new_pos.as_mut_bytes())?;
        self.pos = new_pos;

        Ok(new_pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use std::net::TcpListener;
    use std::net::TcpStream;

    #[test]
    fn test_host_data_storage() {
        // Write data to the storage
        let data = b"Hello, world!";
        let mut cursor = Cursor::new(Vec::new());
        let mut storage = HostFileStorage::new(&mut cursor, WriteLimit::None);
        let header = TransportHeader::new()
            .with_operation(HostFileOperation::WRITE)
            .with_size(data.len());
        let result = storage.transfer(header, HostData::Write(data));
        assert!(result.is_ok());
        assert_eq!(storage.bytes_written(), data.len());
        assert_eq!(storage.bytes_read(), 0);
        assert!(!storage.eof);

        // Seek to the beginning of the storage
        let seek_header = TransportHeader::new()
            .with_operation(HostFileOperation::SEEK)
            .with_seek_pos(SeekPosition::START)
            .with_size(0);
        let result = storage.transfer(seek_header, HostData::Write(&[]));
        assert!(result.is_ok());
        assert_eq!(storage.bytes_written(), data.len());
        assert_eq!(storage.bytes_read(), 0);
        assert!(!storage.eof);

        // Read data from the storage
        let mut buffer = vec![0; data.len()];
        let header = TransportHeader::new()
            .with_operation(HostFileOperation::READ)
            .with_size(data.len());
        let result = storage.transfer(header, HostData::Read(&mut buffer));
        assert!(result.is_ok());
        assert_eq!(buffer, data);
        assert_eq!(storage.bytes_written(), data.len());
        assert_eq!(storage.bytes_read(), data.len());
        assert!(!storage.eof);

        // Test end of file
        let eof_header = TransportHeader::eof();
        let result = storage.transfer(eof_header, HostData::Write(&[]));
        assert!(matches!(result, Err(HostFileError::EndOfFile)));
    }

    #[test]
    fn test_test_loopback() {
        const DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

        let guest_thread = std::thread::spawn(|| {
            let sock = TcpListener::bind((Ipv4Addr::LOCALHOST, 50000)).unwrap();
            let mut stream = sock.accept().unwrap();

            let mut hfa = HostFileAccess::new(&mut stream.0).unwrap();
            hfa.write_all(DATA).unwrap();
            hfa.flush().unwrap();
            hfa.seek(std::io::SeekFrom::Start(0)).unwrap();

            let mut buf = vec![];
            hfa.read_to_end(&mut buf).unwrap();
            assert_eq!(&buf, DATA);
        });

        let host_thread = std::thread::spawn(|| {
            let mut cursor = Cursor::new(Vec::new());
            let mut storage = HostFileStorage::new(&mut cursor, WriteLimit::None);

            let sock = TcpStream::connect((Ipv4Addr::LOCALHOST, 50000)).unwrap();
            storage.run(sock).unwrap();

            cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
            let mut buf = vec![];
            let data = cursor.read_to_end(&mut buf).unwrap();
            assert_eq!(&buf[..data], DATA);
        });

        host_thread.join().unwrap();
        guest_thread.join().unwrap();
    }
}

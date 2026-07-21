using System;
using System.IO;
using System.IO.Compression;

namespace MiniSoftware;

/// <summary>
/// Guards against decompression-bomb attacks in untrusted OOXML (.docx/.xlsx/.pptx) archives
/// by capping how many bytes can actually be read out of a single zip entry, independent of
/// whatever the entry's (attacker-controlled) declared uncompressed size claims.
/// </summary>
internal static class ZipEntrySafety
{
    /// <summary>Maximum bytes a single zip entry is allowed to decompress to before parsing aborts.</summary>
    internal const long MaxEntryUncompressedBytes = 200L * 1024 * 1024; // 200 MB

    /// <summary>
    /// Opens a zip entry for reading, wrapped so that reading more than
    /// <see cref="MaxEntryUncompressedBytes"/> bytes out of it throws instead of continuing
    /// to inflate an attacker-supplied decompression bomb.
    /// </summary>
    internal static Stream OpenBounded(this ZipArchiveEntry entry) =>
        new BoundedReadStream(entry.Open(), MaxEntryUncompressedBytes);

    private sealed class BoundedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _maxBytes;
        private long _totalRead;

        internal BoundedReadStream(Stream inner, long maxBytes)
        {
            _inner = inner;
            _maxBytes = maxBytes;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            if (read > 0)
            {
                _totalRead += read;
                if (_totalRead > _maxBytes)
                    throw new InvalidDataException(
                        $"Archive entry exceeds the maximum allowed decompressed size ({_maxBytes:N0} bytes); refusing to continue reading (possible decompression bomb).");
            }
            return read;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}

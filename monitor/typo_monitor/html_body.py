"""Incremental identity/gzip/zlib-deflate HTML reads with bounded inflation."""

import zlib


class HtmlBody:
    MAX_WIRE_BYTES = 512 * 1024

    def __init__(self, raw, encoding, check_budget):
        if encoding not in {"", "identity", "gzip", "x-gzip", "deflate"}:
            raise ValueError("Unsupported HTML content encoding.")
        self.raw, self.check_budget = raw, check_budget
        self.decoder = (None if encoding in {"", "identity"} else
                        zlib.decompressobj(16 + zlib.MAX_WBITS if encoding in {"gzip", "x-gzip"} else zlib.MAX_WBITS))
        self.pending, self.wire_bytes, self.finished = b"", 0, False

    def _end(self):
        self.check_budget()
        if self.wire_bytes >= self.MAX_WIRE_BYTES:
            raise ValueError("Compressed HTML reached its wire limit before EOF verification.")
        trailing = self.raw.read1(1, decode_content=False)
        self.check_budget()
        if trailing:
            raise ValueError("Trailing compressed HTML data is unsupported.")
        return b""

    def read(self, size):
        """Return at most size decoded bytes; never perform unbounded flush()."""
        self.check_budget()
        if self.decoder is None:
            data = self.raw.read1(size, decode_content=False)
            self.check_budget()
            return data
        while not self.finished:
            self.check_budget()
            if not self.pending:
                remaining = self.MAX_WIRE_BYTES - self.wire_bytes
                if remaining <= 0:
                    raise ValueError("Compressed HTML exceeded its wire limit.")
                self.pending = self.raw.read1(min(4096, remaining), decode_content=False)
                self.check_budget()
                self.wire_bytes += len(self.pending)
                if not self.pending:
                    if not self.decoder.eof:
                        raise ValueError("Incomplete compressed HTML.")
                    self.finished = True
                    return self._end()
            try:
                data = self.decoder.decompress(self.pending, max_length=size)
            except zlib.error as exc:
                raise ValueError("Invalid compressed HTML.") from exc
            self.pending = self.decoder.unconsumed_tail
            if self.decoder.unused_data:
                raise ValueError("Trailing compressed HTML data is unsupported.")
            if self.decoder.eof:
                self.finished = True
            if data:
                return data
        return self._end()

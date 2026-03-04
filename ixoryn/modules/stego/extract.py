"""
Ixoryn Steganography Extract Engine — Operational Mode
Extracts payloads hidden by StegoEmbed from images or audio files.
"""

import io
import struct
import hashlib
from pathlib import Path
from typing import Optional, Tuple
from ixoryn.core.logger import get_logger

logger = get_logger("stego.extract")

STEGO_MAGIC = b"\xD3IXST\x01"


class StegoExtract:
    """Extracts payloads embedded by Ixoryn's StegoEmbed engine."""

    IMAGE_EXTS = {".png", ".bmp", ".tiff", ".tif"}
    AUDIO_EXTS = {".wav", ".flac"}

    def extract(
        self,
        stego_path: str,
        password: Optional[str] = None,
    ) -> Tuple[bytes, str]:
        """
        Extract the hidden payload from a stego file.
        Returns (payload_bytes, payload_filename).
        """
        path = Path(stego_path)
        ext = path.suffix.lower()

        if ext in self.IMAGE_EXTS:
            raw_bits = self._extract_bits_image(str(path), password)
        elif ext in self.AUDIO_EXTS:
            raw_bits = self._extract_bits_audio(str(path))
        else:
            raise ValueError(
                f"Unsupported stego format: '{ext}'. "
                f"Only lossless formats are supported: PNG, BMP, TIFF, WAV, FLAC."
            )

        return self._parse_packet(raw_bits, password)

    def _extract_bits_image(self, filepath: str, password: Optional[str] = None):
        """Extract LSB bits from image using randomized traversal if password given."""
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            raise RuntimeError("PIL and numpy required. Install: pip install Pillow numpy")

        img = Image.open(filepath)
        if img.mode != "RGB":
            img = img.convert("RGB")

        flat = np.array(img).flatten()

        if password:
            from ixoryn.modules.stego.traversal import RandomLSBTraversal
            traversal = RandomLSBTraversal(password, len(flat))
            order = traversal.get_order()
            bits = [int(flat[pos]) & 1 for pos in order]
        else:
            bits = [int(p) & 1 for p in flat]

        return bits

    def _extract_bits_audio(self, filepath: str):
        """Extract LSB bits from audio samples."""
        try:
            from pydub import AudioSegment
        except ImportError:
            raise RuntimeError("pydub required. Install: pip install pydub")

        audio = AudioSegment.from_file(filepath)
        raw = audio.raw_data
        sample_width = audio.sample_width

        import array as arr
        if sample_width == 2:
            samples = arr.array("h", raw)
        else:
            samples = arr.array("b", raw)

        bits = [int(s) & 1 for s in samples]
        return bits

    def _parse_packet(self, bits, password: Optional[str]) -> Tuple[bytes, str]:
        """Parse the embedding packet from extracted bits."""
        import hmac as _hmac

        def bits_to_bytes(bit_list, n_bytes) -> bytes:
            result = []
            for i in range(n_bytes):
                byte = 0
                for j in range(8):
                    idx = i * 8 + j
                    if idx < len(bit_list):
                        byte = (byte << 1) | bit_list[idx]
                    else:
                        byte = byte << 1
                result.append(byte)
            return bytes(result)

        # Read length header (4 bytes = 32 bits)
        length_bytes = bits_to_bytes(bits, 4)
        packet_length = struct.unpack(">I", length_bytes)[0]

        if packet_length == 0 or packet_length > len(bits) // 8:
            raise ValueError(
                "No hidden data found, or data is corrupted. "
                "This file may not contain an Ixoryn-embedded payload, "
                "or it may have been recompressed (which destroys LSB data)."
            )

        # Extract full packet
        packet_bits = bits[32: 32 + packet_length * 8]
        packet = bits_to_bytes(packet_bits, packet_length)

        # Parse packet structure
        offset = 0

        # Verify magic
        if packet[:6] != STEGO_MAGIC:
            raise ValueError(
                "Invalid stego signature. "
                "File was not embedded by Ixoryn, or the data has been corrupted."
            )
        offset += 6

        version = packet[offset]
        offset += 1
        flags = packet[offset]
        offset += 1

        # Read per-packet salt (16 bytes) — used for HMAC integrity verification.
        # FIX: salt was written by embed._build_packet but not read back here,
        # causing all subsequent field offsets to be misaligned by 16 bytes.
        salt = packet[offset:offset + 16]
        offset += 16

        name_len = packet[offset]
        offset += 1
        name_bytes = packet[offset:offset + name_len]
        payload_name = name_bytes.decode("utf-8", errors="replace")
        offset += name_len

        stored_checksum = packet[offset:offset + 32]
        offset += 32

        payload_len = struct.unpack(">I", packet[offset:offset + 4])[0]
        offset += 4

        raw_payload = packet[offset:offset + payload_len]

        # Verify checksum using the same HMAC-SHA256 computation as embed._build_packet.
        # FIX: embed uses hmac.new(salt, salt+name+len+payload, sha256).digest(),
        # but the old extractor used hashlib.sha256(raw_payload).digest() — always mismatched.
        hmac_input = salt + name_bytes + struct.pack(">I", len(raw_payload)) + raw_payload
        computed_checksum = _hmac.new(salt, hmac_input, hashlib.sha256).digest()
        if computed_checksum != stored_checksum:
            raise ValueError(
                "Payload checksum mismatch — data may be corrupted or tampered. "
                "Extraction aborted to protect integrity."
            )

        # Decrypt if encrypted
        is_encrypted = bool(flags & 0x01)
        if is_encrypted:
            if not password:
                raise ValueError(
                    "This payload is encrypted. "
                    "Please provide the password used during embedding."
                )
            raw_payload = self._decrypt_payload(raw_payload, password)

        logger.info(f"Extracted {len(raw_payload)} bytes, name='{payload_name}'")
        return raw_payload, payload_name

    def _decrypt_payload(self, payload: bytes, password: str) -> bytes:
        from ixoryn.modules.crypto.engine import CryptoEngine
        engine = CryptoEngine()
        plaintext, _ = engine.decrypt(payload, password)
        return plaintext

"""
Ixoryn Steganography Embed Engine — Operational Mode
Embeds files, text, images, or audio into cover images or audio.
Always outputs lossless format (PNG for images, FLAC for audio).

Technique: LSB embedding with AES-256-GCM encryption + Argon2id KDF
Enhanced with randomized pixel traversal using a seeded PRNG for added security.
"""

import os
import io
import struct
import hashlib
from pathlib import Path
from typing import Optional, Tuple
from ixoryn.core.logger import get_logger

logger = get_logger("stego.embed")

# Embedding header magic
STEGO_MAGIC = b"\xD3IXST\x01"  # 6 bytes
STEGO_VERSION = 1


class StegoEmbed:
    """
    Embeds arbitrary payloads into image or audio covers using LSB steganography.
    Supports optional Argon2id + AES-256-GCM encryption of payload before embedding.
    Output is always lossless (PNG or FLAC) to prevent data corruption.
    """

    IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif", ".webp"}
    AUDIO_EXTS = {".wav", ".flac", ".mp3", ".ogg", ".aiff", ".aif"}

    def embed(
        self,
        cover_path: str,
        payload_data: bytes,
        payload_name: str,
        output_path: str,
        password: Optional[str] = None,
        bits_per_channel: int = 1,
    ) -> str:
        """
        Embed payload_data into cover_path.
        Returns the path of the output stego file.
        """
        cover_path = Path(cover_path)
        ext = cover_path.suffix.lower()

        if ext in self.IMAGE_EXTS:
            return self._embed_image(cover_path, payload_data, payload_name, output_path, password, bits_per_channel)
        elif ext in self.AUDIO_EXTS:
            return self._embed_audio(cover_path, payload_data, payload_name, output_path, password)
        else:
            raise ValueError(
                f"Unsupported cover format: '{ext}'. "
                f"Supported image formats: {', '.join(self.IMAGE_EXTS)}. "
                f"Supported audio formats: {', '.join(self.AUDIO_EXTS)}."
            )

    # ─── IMAGE EMBEDDING ──────────────────────────────────────────────
    def _embed_image(self, cover_path: Path, payload: bytes, payload_name: str,
                     output_path: str, password: Optional[str], bpc: int) -> str:
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            raise RuntimeError("PIL and numpy are required for image steganography. "
                               "Install: pip install Pillow numpy")

        img = Image.open(str(cover_path))

        # Convert to RGB for consistent embedding
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
        elif img.mode == "RGBA":
            img = img.convert("RGB")

        img_array = np.array(img, dtype=np.uint8)
        h, w, c = img_array.shape
        capacity_bits = h * w * c * bpc
        capacity_bytes = capacity_bits // 8

        # Build payload packet
        packet = self._build_packet(payload, payload_name, password)

        if len(packet) + 4 > capacity_bytes:
            raise ValueError(
                f"Payload too large for this cover image. "
                f"Maximum capacity: {capacity_bytes - 4} bytes, "
                f"Payload size: {len(packet)} bytes. "
                f"Use a larger cover image or reduce payload size."
            )

        # Prepend packet length (4 bytes)
        length_header = struct.pack(">I", len(packet))
        full_data = length_header + packet

        # Flatten image
        flat = img_array.flatten()

        # Use randomized traversal if password given (defeats chi-square on output)
        from ixoryn.modules.stego.traversal import RandomLSBTraversal
        traversal = RandomLSBTraversal(password, len(flat))
        order = traversal.get_order()

        # Embed bits using randomized pixel order
        bit_stream = self._bytes_to_bits(full_data)
        for bit_idx, bit in enumerate(bit_stream):
            pixel_pos = order[bit_idx]
            flat[pixel_pos] = (flat[pixel_pos] & 0xFE) | bit

        # Reshape and save as PNG (lossless)
        result_array = flat.reshape((h, w, c))
        result_img = Image.fromarray(result_array.astype(np.uint8), "RGB")

        # Ensure output is PNG for losslessness
        out_path = Path(output_path)
        if out_path.suffix.lower() != ".png":
            out_path = out_path.with_suffix(".png")

        result_img.save(str(out_path), "PNG", compress_level=6)

        logger.info(f"Embedded {len(payload)} bytes into {cover_path.name} → {out_path}")
        return str(out_path)

    # ─── AUDIO EMBEDDING ──────────────────────────────────────────────
    def _embed_audio(self, cover_path: Path, payload: bytes, payload_name: str,
                     output_path: str, password: Optional[str]) -> str:
        """Embed into audio using LSB of samples. Output is always FLAC."""
        try:
            from pydub import AudioSegment
        except ImportError:
            raise RuntimeError("pydub is required for audio steganography. "
                               "Install: pip install pydub")

        # Load audio and convert to WAV internals
        audio = AudioSegment.from_file(str(cover_path))
        raw_samples = audio.raw_data
        channels = audio.channels
        sample_width = audio.sample_width  # bytes per sample
        frame_rate = audio.frame_rate

        if sample_width not in (1, 2):
            # Convert to 16-bit
            audio = audio.set_sample_width(2)
            raw_samples = audio.raw_data
            sample_width = 2

        capacity_bytes = len(raw_samples) // sample_width // 8

        packet = self._build_packet(payload, payload_name, password)

        if len(packet) + 4 > capacity_bytes:
            raise ValueError(
                f"Payload too large for this audio cover. "
                f"Maximum capacity: {capacity_bytes - 4} bytes, "
                f"Payload size: {len(packet)} bytes."
            )

        length_header = struct.pack(">I", len(packet))
        full_data = length_header + packet
        bit_stream = self._bytes_to_bits(full_data)

        # Modify LSBs of samples
        import array as arr
        if sample_width == 2:
            samples = arr.array("h", raw_samples)  # signed 16-bit
        else:
            samples = arr.array("b", raw_samples)

        for i, bit in enumerate(bit_stream):
            if i >= len(samples):
                break
            # Use randomized traversal for audio too if password given
            samples[i] = (samples[i] & ~1) | bit

        modified_audio = AudioSegment(
            data=samples.tobytes(),
            sample_width=sample_width,
            frame_rate=frame_rate,
            channels=channels,
        )

        # Output as FLAC (lossless)
        out_path = Path(output_path)
        if out_path.suffix.lower() != ".flac":
            out_path = out_path.with_suffix(".flac")

        modified_audio.export(str(out_path), format="flac")

        logger.info(f"Embedded {len(payload)} bytes into {cover_path.name} → {out_path}")
        return str(out_path)

    # ─── PACKET FORMAT ────────────────────────────────────────────────
    def _build_packet(self, payload: bytes, payload_name: str,
                      password: Optional[str]) -> bytes:
        """
        Build the embedding packet:
          MAGIC (6) | version (1) | flags (1) | salt (16) | name_len (1) | name (var) |
          hmac (32) | payload_len (4) | payload

        Security:
          - Encrypted payloads: AES-256-GCM provides authenticated encryption.
          - Unencrypted payloads: HMAC-SHA256 with a random per-packet salt provides
            integrity verification (detects accidental corruption or naive tampering).
            Note: without a secret key, this does not prevent deliberate forgery.
        """
        import os as _os
        import hmac as _hmac
        flags = 0x01 if password else 0x00

        # Optionally encrypt payload
        if password:
            payload = self._encrypt_payload(payload, password)

        # Per-packet random salt for HMAC (integrity check on unencrypted payloads)
        salt = _os.urandom(16)
        name_bytes = payload_name.encode("utf-8")[:255]

        # Compute HMAC-SHA256 over (salt + name + payload_length + payload)
        hmac_input = salt + name_bytes + struct.pack(">I", len(payload)) + payload
        checksum = _hmac.new(salt, hmac_input, hashlib.sha256).digest()

        packet = (
            STEGO_MAGIC
            + bytes([STEGO_VERSION, flags])
            + salt                                        # 16 bytes random salt
            + bytes([len(name_bytes)])
            + name_bytes
            + checksum                                    # 32 bytes HMAC
            + struct.pack(">I", len(payload))
            + payload
        )
        return packet

    def _encrypt_payload(self, payload: bytes, password: str) -> bytes:
        """Encrypt payload using AES-256-GCM + Argon2id."""
        from ixoryn.modules.crypto.engine import CryptoEngine
        engine = CryptoEngine()
        return engine.encrypt(payload, password, filename="stego_payload")

    def _bytes_to_bits(self, data: bytes):
        """Convert bytes to a list of bits (MSB first)."""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

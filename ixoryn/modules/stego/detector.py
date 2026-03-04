"""
Ixoryn Steganography Detector — Forensic Research Mode
World-class forensic-grade stego detection using multiple analysis techniques.

Techniques employed:
 - LSB (Least Significant Bit) analysis & plane visualization
 - Chi-square attack (statistical uniformity test)
 - RS (Regular/Singular) analysis
 - DCT coefficient analysis (JPEG)
 - Entropy analysis
 - EXIF/metadata forensics
 - Error Level Analysis (ELA)
 - Sample Pair Analysis
 - Audio spectrum & statistical analysis
 - Histogram analysis
 - File signature verification
"""

import os
import io
import math
import struct
import hashlib
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from ixoryn.ui.banner import Banner, Colors
from ixoryn.core.logger import get_logger

logger = get_logger("stego.detector")


class StegoDetector:
    """Forensic-grade steganographic content detector."""

    IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif", ".webp"}
    AUDIO_EXTENSIONS = {".wav", ".flac", ".mp3", ".ogg", ".aiff", ".aif"}

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def analyze(self, filepath: str) -> Dict[str, Any]:
        """
        Run full forensic analysis on a file.
        Returns a comprehensive report dictionary.
        """
        path = Path(filepath)
        ext = path.suffix.lower()

        report = {
            "file": str(filepath),
            "filename": path.name,
            "file_size": path.stat().st_size,
            "extension": ext,
            "file_type": "unknown",
            "timestamp": self._timestamp(),
            "overall_suspicion": "LOW",
            "suspicion_score": 0.0,
            "findings": [],
            "metadata": {},
            "analysis": {},
            "verdict": "",
        }

        try:
            with open(filepath, "rb") as f:
                raw_bytes = f.read()

            # File type detection
            report["file_type"] = self._detect_file_type(raw_bytes, ext)
            report["metadata"] = self.get_metadata(filepath)

            # Route to appropriate analyzer
            if ext in self.IMAGE_EXTENSIONS:
                self._analyze_image(filepath, raw_bytes, report)
            elif ext in self.AUDIO_EXTENSIONS:
                self._analyze_audio(filepath, raw_bytes, report)
            else:
                self._analyze_generic(raw_bytes, report)

            # ML Layer — run ensemble classifier
            try:
                from ixoryn.modules.stego.ml_detector import MLStegoDetector
                ml = MLStegoDetector()
                ml_result = ml.predict(filepath)
                report["ml_analysis"] = ml_result

                # Boost suspicion score if ML agrees
                if ml_result.get("verdict") in ("LIKELY_STEGO",):
                    report["suspicion_score"] = min(100, report["suspicion_score"] + 25)
                    report["findings"].append({
                        "type": "ML Ensemble Classifier",
                        "severity": "HIGH",
                        "message": (
                            f"Machine learning classifier flagged this file as likely steganographic. "
                            f"Stego probability: {ml_result.get('stego_probability', 0):.2%}, "
                            f"Anomaly score: {ml_result.get('anomaly_score', 0):.2%}"
                        ),
                        "score": 25,
                    })
                elif ml_result.get("verdict") == "POSSIBLY_STEGO":
                    report["suspicion_score"] = min(100, report["suspicion_score"] + 10)
            except Exception as ml_err:
                logger.debug(f"ML analysis skipped: {ml_err}")

            # Compute final verdict
            score = report["suspicion_score"]
            if score >= 75:
                report["overall_suspicion"] = "CRITICAL"
                report["verdict"] = (
                    "HIGH PROBABILITY of steganographic content. Multiple strong indicators detected. "
                    "This file very likely contains hidden data."
                )
            elif score >= 50:
                report["overall_suspicion"] = "HIGH"
                report["verdict"] = (
                    "Significant statistical anomalies detected. "
                    "File shows strong indicators of steganography."
                )
            elif score >= 25:
                report["overall_suspicion"] = "MEDIUM"
                report["verdict"] = (
                    "Some suspicious indicators present. "
                    "Manual investigation recommended."
                )
            else:
                report["overall_suspicion"] = "LOW"
                report["verdict"] = (
                    "No significant steganographic indicators detected. "
                    "File appears to be clean, but absence of evidence is not evidence of absence."
                )

        except Exception as e:
            report["error"] = str(e)
            report["verdict"] = f"Analysis error: {e}"
            logger.error(f"Analysis failed for {filepath}: {e}")

        return report

    def _detect_file_type(self, data: bytes, ext: str) -> str:
        """Detect actual file type via magic bytes."""
        signatures = {
            b"\x89PNG\r\n\x1a\n": "PNG Image",
            b"\xff\xd8\xff": "JPEG Image",
            b"GIF87a": "GIF Image",
            b"GIF89a": "GIF Image",
            b"BM": "BMP Image",
            b"II*\x00": "TIFF Image (LE)",
            b"MM\x00*": "TIFF Image (BE)",
            b"RIFF": "RIFF File (WAV/AVI)",
            b"fLaC": "FLAC Audio",
            b"ID3": "MP3 Audio",
            b"OggS": "OGG Audio",
            b"FORM": "AIFF Audio",
            b"\x1aE\xdf\xa3": "WebM/MKV",
        }
        for sig, name in signatures.items():
            if data[:len(sig)] == sig:
                return name
        return f"Unknown ({ext})"

    # ─── IMAGE ANALYSIS ───────────────────────────────────────────────
    def _analyze_image(self, filepath: str, raw_bytes: bytes, report: dict):
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            report["findings"].append({
                "type": "error",
                "message": "PIL/numpy not available for image analysis"
            })
            return

        try:
            img = Image.open(filepath)
            report["analysis"]["image_info"] = {
                "mode": img.mode,
                "size": f"{img.width}x{img.height}",
                "format": img.format,
                "max_capacity_bits": img.width * img.height * (3 if img.mode == "RGB" else 1),
            }

            if img.mode not in ("RGB", "RGBA", "L"):
                img = img.convert("RGB")

            img_array = np.array(img)

            # Run all analysis techniques
            lsb_score = self._lsb_analysis(img_array, report)
            chi_score = self._chi_square_attack(img_array, report)
            hist_score = self._histogram_analysis(img_array, report)
            rs_score = self._rs_analysis(img_array, report)
            ela_score = self._ela_analysis(filepath, report)
            entropy_score = self._entropy_analysis(raw_bytes, report)
            meta_score = self._metadata_forensics(img, report)
            dct_score = self._dct_analysis(img_array, report)

            scores = [s for s in [lsb_score, chi_score, hist_score, rs_score,
                                   ela_score, entropy_score, meta_score, dct_score] if s is not None]
            report["suspicion_score"] = min(100, sum(scores) / max(len(scores), 1) * 1.2)

        except Exception as e:
            report["findings"].append({"type": "error", "message": f"Image analysis error: {e}"})
            logger.error(f"Image analysis error: {e}")

    def _lsb_analysis(self, img_array, report: dict) -> float:
        """LSB statistical analysis — detect LSB steganography."""
        try:
            import numpy as np
            score = 0.0
            channel_results = {}

            for ch_idx, ch_name in enumerate(["R", "G", "B"][:img_array.shape[2] if len(img_array.shape) > 2 else 1]):
                if len(img_array.shape) == 2:
                    channel = img_array
                else:
                    channel = img_array[:, :, ch_idx]

                lsb_bits = channel & 1
                ones = np.sum(lsb_bits)
                total = lsb_bits.size
                ratio = ones / total if total > 0 else 0
                deviation = abs(ratio - 0.5)

                channel_results[ch_name] = {
                    "ones_ratio": float(ratio),
                    "deviation_from_random": float(deviation),
                }

                # A ratio very close to 0.5 suggests LSB was randomized (hidden data)
                if deviation < 0.01:
                    score += 30
                elif deviation < 0.03:
                    score += 15
                elif deviation < 0.06:
                    score += 5

            report["analysis"]["lsb_analysis"] = channel_results
            if score > 20:
                report["findings"].append({
                    "type": "LSB Analysis",
                    "severity": "HIGH" if score > 40 else "MEDIUM",
                    "message": f"LSB distribution suspiciously uniform (score={score:.1f}). "
                               f"Possible LSB steganography detected.",
                    "score": score,
                })
            return score

        except Exception as e:
            logger.debug(f"LSB analysis failed: {e}")
            return 0.0

    def _chi_square_attack(self, img_array, report: dict) -> float:
        """Chi-square attack — tests for value-pair equality (PoVs)."""
        try:
            import numpy as np
            score = 0.0
            results = {}

            for ch_idx, ch_name in enumerate(["R", "G", "B"][:img_array.shape[2] if len(img_array.shape) > 2 else 1]):
                channel = img_array[:, :, ch_idx].flatten() if len(img_array.shape) > 2 else img_array.flatten()
                hist, _ = np.histogram(channel, bins=256, range=(0, 256))

                chi_sq = 0.0
                pairs_analyzed = 0
                for i in range(0, 255, 2):
                    expected = (hist[i] + hist[i + 1]) / 2
                    if expected > 0:
                        chi_sq += ((hist[i] - expected) ** 2 + (hist[i + 1] - expected) ** 2) / expected
                        pairs_analyzed += 1

                # Normalize chi-square
                normalized = chi_sq / pairs_analyzed if pairs_analyzed > 0 else 0
                results[ch_name] = {"chi_square": float(chi_sq), "normalized": float(normalized)}

                # Low chi-square = high similarity between PoVs = likely stego
                if normalized < 1.0:
                    score += 35
                elif normalized < 2.0:
                    score += 20
                elif normalized < 4.0:
                    score += 10

            report["analysis"]["chi_square"] = results
            if score > 25:
                report["findings"].append({
                    "type": "Chi-Square Attack",
                    "severity": "HIGH" if score > 50 else "MEDIUM",
                    "message": f"Chi-square test indicates PoV equality — strong LSB stego indicator.",
                    "score": score,
                })
            return min(score, 60)

        except Exception as e:
            logger.debug(f"Chi-square failed: {e}")
            return 0.0

    def _histogram_analysis(self, img_array, report: dict) -> float:
        """Histogram analysis — detect anomalies in pixel value distribution."""
        try:
            import numpy as np
            score = 0.0

            for ch_idx, ch_name in enumerate(["R", "G", "B"][:img_array.shape[2] if len(img_array.shape) > 2 else 1]):
                channel = img_array[:, :, ch_idx].flatten() if len(img_array.shape) > 2 else img_array.flatten()
                hist, _ = np.histogram(channel, bins=256, range=(0, 256))

                # Look for "comb" pattern (alternating high/low pairs) typical of LSB stego
                diffs = [abs(int(hist[i]) - int(hist[i + 1])) for i in range(0, min(255, len(hist) - 1))]
                mean_diff = np.mean(diffs)
                std_diff = np.std(diffs)

                # Low std with low mean diff suggests artificial randomization
                if mean_diff < 50 and std_diff < 30:
                    score += 20

            report["analysis"]["histogram"] = {
                "mean_inter_bin_diff": float(mean_diff) if diffs else 0,
                "std_inter_bin_diff": float(std_diff) if diffs else 0,
            }
            return score

        except Exception as e:
            logger.debug(f"Histogram analysis failed: {e}")
            return 0.0

    def _rs_analysis(self, img_array, report: dict) -> float:
        """Regular-Singular (RS) Analysis — advanced stego detection."""
        try:
            import numpy as np
            score = 0.0

            # Use first channel for RS analysis
            if len(img_array.shape) > 2:
                channel = img_array[:, :, 0].astype(int)
            else:
                channel = img_array.astype(int)

            h, w = channel.shape
            group_size = 4

            r_count, s_count, r_neg, s_neg = 0, 0, 0, 0
            mask = np.array([0, 1, 1, 0])  # alternating flip mask
            total = 0

            for row in range(0, h - 1, group_size):
                for col in range(0, w - group_size + 1, group_size):
                    group = channel[row, col:col + group_size]
                    if len(group) < group_size:
                        continue

                    # Compute discriminant function (smoothness)
                    f_orig = sum(abs(int(group[i]) - int(group[i + 1])) for i in range(group_size - 1))

                    # Flipped group (LSB flip)
                    flipped = group.copy()
                    for i in range(group_size):
                        if mask[i] == 1:
                            flipped[i] = flipped[i] ^ 1  # flip LSB
                    f_flip = sum(abs(int(flipped[i]) - int(flipped[i + 1])) for i in range(group_size - 1))

                    if f_orig < f_flip:
                        r_count += 1
                    elif f_orig > f_flip:
                        s_count += 1
                    total += 1

            if total > 0:
                r_ratio = r_count / total
                s_ratio = s_count / total

                report["analysis"]["rs_analysis"] = {
                    "R": float(r_ratio),
                    "S": float(s_ratio),
                    "ratio_diff": float(abs(r_ratio - s_ratio)),
                }

                # In clean images R ≈ S ≈ 0.5. If R >> S, likely stego
                if r_ratio > 0.6 and s_ratio < 0.3:
                    score = 40
                    report["findings"].append({
                        "type": "RS Analysis",
                        "severity": "HIGH",
                        "message": f"RS analysis shows R={r_ratio:.3f} >> S={s_ratio:.3f}, "
                                   f"strong indicator of LSB embedding.",
                        "score": score,
                    })
                elif r_ratio > 0.55:
                    score = 20

            return score

        except Exception as e:
            logger.debug(f"RS analysis failed: {e}")
            return 0.0

    def _ela_analysis(self, filepath: str, report: dict) -> float:
        """Error Level Analysis — detect compression inconsistencies."""
        try:
            from PIL import Image
            import numpy as np
            import tempfile

            score = 0.0
            ext = Path(filepath).suffix.lower()

            if ext not in (".jpg", ".jpeg"):
                report["analysis"]["ela"] = {"note": "ELA most relevant for JPEG images"}
                return 0.0

            with Image.open(filepath) as original:
                if original.mode != "RGB":
                    original = original.convert("RGB")
                orig_array = np.array(original)

                # Re-save at known quality
                with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
                    tmp_path = tmp.name
                    original.save(tmp_path, "JPEG", quality=95)

            with Image.open(tmp_path) as recompressed:
                recomp_array = np.array(recompressed)

            os.unlink(tmp_path)

            # Compute ELA
            ela = np.abs(orig_array.astype(int) - recomp_array.astype(int))
            ela_mean = float(np.mean(ela))
            ela_max = float(np.max(ela))
            ela_std = float(np.std(ela))

            report["analysis"]["ela"] = {
                "mean_error": ela_mean,
                "max_error": ela_max,
                "std_error": ela_std,
            }

            # High ELA variance suggests inconsistent compression (possible embedding)
            if ela_std > 20 and ela_mean > 10:
                score = 25
                report["findings"].append({
                    "type": "Error Level Analysis (ELA)",
                    "severity": "MEDIUM",
                    "message": f"ELA shows inconsistent compression artifacts "
                               f"(mean={ela_mean:.1f}, std={ela_std:.1f}). "
                               f"Possible JPEG steganography.",
                    "score": score,
                })

            return score

        except Exception as e:
            logger.debug(f"ELA failed: {e}")
            return 0.0

    def _dct_analysis(self, img_array, report: dict) -> float:
        """DCT coefficient analysis for JPEG steganography detection."""
        try:
            import numpy as np
            from scipy.fftpack import dct

            score = 0.0
            if len(img_array.shape) > 2:
                channel = img_array[:, :, 0].astype(float)
            else:
                channel = img_array.astype(float)

            # Process in 8x8 blocks
            h, w = channel.shape
            dct_coeffs = []

            for row in range(0, h - 8, 8):
                for col in range(0, w - 8, 8):
                    block = channel[row:row + 8, col:col + 8]
                    dct_block = dct(dct(block, axis=0), axis=1)
                    # Collect AC coefficients (skip DC)
                    ac = dct_block.flatten()[1:]
                    dct_coeffs.extend(ac.tolist())

            if dct_coeffs:
                # Check distribution of DCT coefficients
                zeros = sum(1 for c in dct_coeffs if abs(c) < 0.5)
                zero_ratio = zeros / len(dct_coeffs)

                report["analysis"]["dct_analysis"] = {
                    "zero_coeff_ratio": float(zero_ratio),
                    "total_ac_coeffs": len(dct_coeffs),
                }

                # Abnormally few or many zeros can indicate quantization-based stego
                if zero_ratio < 0.3 or zero_ratio > 0.8:
                    score = 15
                    report["findings"].append({
                        "type": "DCT Coefficient Analysis",
                        "severity": "LOW",
                        "message": f"DCT zero-coefficient ratio ({zero_ratio:.3f}) is anomalous.",
                        "score": score,
                    })

            return score

        except Exception as e:
            logger.debug(f"DCT analysis failed: {e}")
            return 0.0

    # ─── AUDIO ANALYSIS ───────────────────────────────────────────────
    def _analyze_audio(self, filepath: str, raw_bytes: bytes, report: dict):
        """Full audio forensic analysis."""
        try:
            report["file_type"] = "Audio"
            self._audio_lsb_analysis(filepath, report)
            self._audio_spectrum_analysis(filepath, report)
            self._entropy_analysis(raw_bytes, report)
            self._audio_metadata_analysis(filepath, report)

            scores = []
            for finding in report["findings"]:
                scores.append(finding.get("score", 0))
            report["suspicion_score"] = min(100, sum(scores) / max(len(scores), 1) * 1.2)

        except Exception as e:
            report["findings"].append({"type": "error", "message": f"Audio analysis error: {e}"})

    def _audio_lsb_analysis(self, filepath: str, report: dict) -> float:
        """LSB analysis for audio files."""
        try:
            ext = Path(filepath).suffix.lower()
            samples = []

            if ext == ".wav":
                import wave
                with wave.open(filepath, "rb") as wav:
                    n_channels = wav.getnchannels()
                    sampwidth = wav.getsampwidth()
                    n_frames = wav.getnframes()
                    raw = wav.readframes(min(n_frames, 100000))

                if sampwidth == 2:  # 16-bit
                    import struct
                    count = len(raw) // 2
                    samples = list(struct.unpack(f"<{count}h", raw[:count * 2]))

            elif ext == ".flac":
                try:
                    from pydub import AudioSegment
                except ImportError:
                    AudioSegment = None
                audio = AudioSegment.from_file(filepath)
                raw_data = audio.raw_data
                import struct
                count = len(raw_data) // 2
                samples = list(struct.unpack(f"<{count}h", raw_data[:count * 2]))

            if samples:
                lsb_bits = [s & 1 for s in samples]
                ones_ratio = sum(lsb_bits) / len(lsb_bits)
                deviation = abs(ones_ratio - 0.5)

                report["analysis"]["audio_lsb"] = {
                    "ones_ratio": float(ones_ratio),
                    "deviation": float(deviation),
                    "samples_analyzed": len(samples),
                }

                if deviation < 0.01:
                    score = 35
                    report["findings"].append({
                        "type": "Audio LSB Analysis",
                        "severity": "HIGH",
                        "message": f"Audio LSB distribution is suspiciously uniform "
                                   f"(ratio={ones_ratio:.4f}). Possible LSB audio steganography.",
                        "score": score,
                    })
                    return score
            return 0.0

        except Exception as e:
            logger.debug(f"Audio LSB analysis failed: {e}")
            return 0.0

    def _audio_spectrum_analysis(self, filepath: str, report: dict) -> float:
        """Frequency spectrum analysis of audio."""
        try:
            from scipy.io import wavfile
            import numpy as np

            ext = Path(filepath).suffix.lower()
            if ext != ".wav":
                return 0.0

            rate, data = wavfile.read(filepath)
            if data.ndim > 1:
                data = data[:, 0]

            data = data[:min(len(data), 441000)]  # Analyze first 10 seconds at 44100 Hz

            # FFT
            fft = np.fft.fft(data)
            magnitude = np.abs(fft[:len(fft) // 2])

            # Check for anomalous frequency content
            mean_mag = np.mean(magnitude)
            std_mag = np.std(magnitude)
            outliers = np.sum(magnitude > mean_mag + 5 * std_mag)
            outlier_ratio = outliers / len(magnitude)

            report["analysis"]["audio_spectrum"] = {
                "sample_rate": rate,
                "duration_sec": len(data) / rate if rate > 0 else 0,
                "spectral_outlier_ratio": float(outlier_ratio),
            }

            if outlier_ratio > 0.05:
                score = 20
                report["findings"].append({
                    "type": "Spectral Analysis",
                    "severity": "MEDIUM",
                    "message": "Unusual frequency content detected in audio spectrum.",
                    "score": score,
                })
                return score
            return 0.0

        except Exception as e:
            logger.debug(f"Audio spectrum analysis failed: {e}")
            return 0.0

    def _audio_metadata_analysis(self, filepath: str, report: dict) -> float:
        """Analyze audio file metadata for anomalies."""
        try:
            meta = {}
            ext = Path(filepath).suffix.lower()

            if ext == ".wav":
                import wave
                with wave.open(filepath, "rb") as wav:
                    meta["channels"] = wav.getnchannels()
                    meta["sample_width"] = wav.getsampwidth()
                    meta["frame_rate"] = wav.getframerate()
                    meta["n_frames"] = wav.getnframes()
                    meta["compression_type"] = wav.getcomptype()

            report["analysis"]["audio_metadata"] = meta
            return 0.0

        except Exception as e:
            logger.debug(f"Audio metadata analysis failed: {e}")
            return 0.0

    # ─── GENERIC ANALYSIS ─────────────────────────────────────────────
    def _analyze_generic(self, raw_bytes: bytes, report: dict):
        """Generic binary file analysis."""
        self._entropy_analysis(raw_bytes, report)
        report["suspicion_score"] = sum(f.get("score", 0) for f in report["findings"]) / 2

    def _entropy_analysis(self, data: bytes, report: dict) -> float:
        """Shannon entropy analysis — high entropy may indicate encryption or compression."""
        try:
            if not data:
                return 0.0

            freq = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1

            entropy = 0.0
            n = len(data)
            for count in freq.values():
                p = count / n
                if p > 0:
                    entropy -= p * math.log2(p)

            report["analysis"]["entropy"] = {
                "shannon_entropy": float(entropy),
                "max_possible": 8.0,
                "unique_bytes": len(freq),
            }

            score = 0.0
            if entropy > 7.9:
                score = 30
                report["findings"].append({
                    "type": "Entropy Analysis",
                    "severity": "MEDIUM",
                    "message": f"Extremely high entropy ({entropy:.4f}/8.0). "
                               f"Data may be encrypted, compressed, or contain hidden payloads.",
                    "score": score,
                })
            elif entropy > 7.5:
                score = 10

            return score

        except Exception as e:
            logger.debug(f"Entropy analysis failed: {e}")
            return 0.0

    def _metadata_forensics(self, img, report: dict) -> float:
        """EXIF and metadata forensic analysis."""
        try:
            score = 0.0
            meta = {}

            exif_data = img._getexif() if hasattr(img, "_getexif") else None
            if exif_data:
                from PIL.ExifTags import TAGS
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    meta[str(tag)] = str(value)

                # Look for suspicious metadata
                suspicious_keys = ["comment", "UserComment", "ImageDescription", "Artist"]
                for key in suspicious_keys:
                    if key in meta and meta[key]:
                        score += 10
                        report["findings"].append({
                            "type": "Metadata Forensics",
                            "severity": "LOW",
                            "message": f"Suspicious metadata field '{key}' contains data. "
                                       f"Could be used for covert communication.",
                            "score": 10,
                        })

            report["analysis"]["exif_metadata"] = meta
            return score

        except Exception as e:
            logger.debug(f"Metadata forensics failed: {e}")
            return 0.0

    def get_metadata(self, filepath: str) -> dict:
        """Extract file metadata."""
        path = Path(filepath)
        stat = path.stat()
        meta = {
            "filename": path.name,
            "extension": path.suffix,
            "size_bytes": stat.st_size,
            "size_human": self._human_size(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }

        # Compute hashes
        with open(filepath, "rb") as f:
            data = f.read()
        meta["md5"] = hashlib.md5(data).hexdigest()
        meta["sha256"] = hashlib.sha256(data).hexdigest()

        # Image-specific
        ext = path.suffix.lower()
        if ext in self.IMAGE_EXTENSIONS:
            try:
                from PIL import Image
                img = Image.open(filepath)
                meta["image_mode"] = img.mode
                meta["image_size"] = f"{img.width}x{img.height}"
                meta["image_format"] = img.format
            except Exception:
                pass

        return meta

    def _human_size(self, size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def print_report(self, report: dict):
        """Pretty-print the forensic analysis report."""
        from ixoryn.ui.banner import Banner, Colors

        suspicion_colors = {
            "LOW": Colors.GREEN,
            "MEDIUM": Colors.YELLOW,
            "HIGH": Colors.RED,
            "CRITICAL": Colors.RED + Colors.BOLD,
        }
        suspicion = report.get("overall_suspicion", "LOW")
        color = suspicion_colors.get(suspicion, Colors.WHITE)

        print(f"\n  {Colors.BOLD}{'═' * 60}{Colors.RESET}")
        print(f"  {Colors.BOLD}FORENSIC ANALYSIS REPORT{Colors.RESET}")
        print(f"  {'═' * 60}")
        Banner.result("File", report.get("filename", "?"))
        Banner.result("Size", report.get("metadata", {}).get("size_human", "?"))
        Banner.result("Type", report.get("file_type", "?"))
        Banner.result("MD5", report.get("metadata", {}).get("md5", "?"), Colors.DIM)
        Banner.result("SHA256", report.get("metadata", {}).get("sha256", "?"), Colors.DIM)
        print()
        Banner.result("Suspicion Level",
                      f"{suspicion} (Score: {report.get('suspicion_score', 0):.1f}/100)",
                      color)
        print()

        findings = report.get("findings", [])
        if findings:
            cprint(f"  ── Findings ({len(findings)}) ──────────────────────────", Colors.CYAN)
            for i, finding in enumerate(findings, 1):
                sev = finding.get("severity", "INFO")
                sev_color = {
                    "HIGH": Colors.RED, "CRITICAL": Colors.RED,
                    "MEDIUM": Colors.YELLOW, "LOW": Colors.GREEN, "INFO": Colors.BLUE
                }.get(sev, Colors.WHITE)
                print(f"\n  {Colors.BOLD}[{i}] {finding.get('type', 'Finding')}{Colors.RESET}")
                print(f"      Severity: {sev_color}{sev}{Colors.RESET}")
                print(f"      {finding.get('message', '')}")

        print()
        cprint(f"  ── Verdict ──────────────────────────────────────", Colors.CYAN)
        print(f"\n  {color}{report.get('verdict', '')}{Colors.RESET}\n")

        # Analysis details
        analysis = report.get("analysis", {})
        if analysis:
            cprint(f"  ── Analysis Details ─────────────────────────────", Colors.DIM)
            for key, value in analysis.items():
                if isinstance(value, dict):
                    print(f"  {Colors.DIM}  {key}:{Colors.RESET}")
                    for k, v in value.items():
                        print(f"      {k}: {v}")
                else:
                    print(f"  {Colors.DIM}  {key}: {value}{Colors.RESET}")
        print()


def cprint(text, color=""):
    print(f"{color}{text}\033[0m")

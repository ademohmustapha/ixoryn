import os
import mimetypes
from core.errors import FileValidationError

ALLOWED_IMAGE_TYPES = {"image/png", "image/bmp"}
ALLOWED_AUDIO_TYPES = {"audio/wav"}
MAX_FILE_SIZE_MB = 50


def validate_file(path, allowed_types):
    if not os.path.exists(path):
        raise FileValidationError("File does not exist.")

    size_mb = os.path.getsize(path) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise FileValidationError("File too large.")

    mime, _ = mimetypes.guess_type(path)
    if mime not in allowed_types:
        raise FileValidationError(
            f"Unsupported file type: {mime}"
        )

    return True


class IXORYNError(Exception):
    """Base class for all IXORYN errors."""
    user_message = "An internal error occurred."

    def __init__(self, message=None):
        super().__init__(message)
        if message:
            self.user_message = message


class UserInputError(IXORYNError):
    user_message = "Invalid input provided."


class FileValidationError(IXORYNError):
    user_message = "Invalid or unsupported file."


class CryptoError(IXORYNError):
    user_message = "Cryptographic operation failed."


class StegoError(IXORYNError):
    user_message = "Steganography operation failed."


class NetworkAnalysisError(IXORYNError):
    user_message = "Domain or URL analysis failed."


class DependencyError(IXORYNError):
    user_message = "Required dependency missing or invalid."


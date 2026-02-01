from core.errors import IXORYNError
from core.logger import logger
import sys


def run_safely(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)

    except IXORYNError as e:
        logger.warning(e.user_message)
        print(f"[!] {e.user_message}")

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        logger.info("User interrupted execution.")
        sys.exit(0)

    except Exception as e:
        logger.exception("Unhandled system error")
        print("[!] A critical internal error occurred.")


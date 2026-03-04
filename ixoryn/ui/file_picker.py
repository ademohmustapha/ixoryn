"""
Ixoryn File Picker
Cross-platform GUI file picker with terminal fallback.
"""

import os
import sys
import platform
from pathlib import Path
from typing import Optional, List


def pick_file(
    title: str = "Select a file",
    filetypes: Optional[List[tuple]] = None,
    initialdir: Optional[str] = None
) -> Optional[str]:
    """
    Open a GUI file picker. Falls back to terminal input if GUI unavailable.
    Returns selected file path or None if cancelled.
    """
    if initialdir is None:
        initialdir = str(Path.home())

    # Try tkinter GUI picker first
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        if filetypes is None:
            filetypes = [("All files", "*.*")]

        filepath = filedialog.askopenfilename(
            title=title,
            initialdir=initialdir,
            filetypes=filetypes
        )
        root.destroy()

        if filepath:
            return filepath
        return None

    except Exception:
        # Fallback to terminal input
        return _terminal_picker(title, initialdir)


def pick_save_file(
    title: str = "Save file as",
    defaultextension: str = ".png",
    filetypes: Optional[List[tuple]] = None,
    initialdir: Optional[str] = None
) -> Optional[str]:
    """Open a GUI save dialog. Falls back to terminal input."""
    if initialdir is None:
        initialdir = str(Path.home())

    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        if filetypes is None:
            filetypes = [("All files", "*.*")]

        filepath = filedialog.asksaveasfilename(
            title=title,
            initialdir=initialdir,
            defaultextension=defaultextension,
            filetypes=filetypes
        )
        root.destroy()

        if filepath:
            return filepath
        return None

    except Exception:
        return _terminal_save_picker(title, defaultextension)


def pick_directory(title: str = "Select directory") -> Optional[str]:
    """Open a GUI directory picker. Falls back to terminal."""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        dirpath = filedialog.askdirectory(title=title)
        root.destroy()

        if dirpath:
            return dirpath
        return None
    except Exception:
        return _terminal_dir_picker(title)


def _terminal_picker(title: str, initialdir: str) -> Optional[str]:
    """Terminal-based file browser."""
    from ixoryn.ui.banner import Colors

    print(f"\n{Colors.CYAN}  [File Browser] {title}{Colors.RESET}")
    print(f"  {Colors.DIM}(GUI not available, using terminal browser){Colors.RESET}\n")

    current = Path(initialdir)

    while True:
        print(f"\n{Colors.YELLOW}  Current directory: {current}{Colors.RESET}")
        try:
            items = sorted(current.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        except PermissionError:
            print(f"{Colors.RED}  Permission denied. Going up...{Colors.RESET}")
            current = current.parent
            continue

        dirs = [i for i in items if i.is_dir()]
        files = [i for i in items if i.is_file()]

        idx = 0
        print(f"  {Colors.DIM}  0) .. (go up){Colors.RESET}")

        for d in dirs:
            idx += 1
            print(f"  {Colors.BLUE}  {idx}) [DIR] {d.name}{Colors.RESET}")

        for f in files:
            idx += 1
            size = f.stat().st_size
            size_str = _human_size(size)
            print(f"  {Colors.WHITE}  {idx}) {f.name}  {Colors.DIM}({size_str}){Colors.RESET}")

        print(f"\n  {Colors.DIM}Type number to select, 'q' to cancel, or paste full path:{Colors.RESET}")

        choice = input(f"  {Colors.MAGENTA}> {Colors.RESET}").strip()

        if choice.lower() == 'q':
            return None

        # Full path pasted
        if os.sep in choice or choice.startswith("/") or (len(choice) > 2 and choice[1] == ":"):
            p = Path(choice)
            if p.is_file():
                return str(p)
            elif p.is_dir():
                current = p
                continue
            else:
                print(f"{Colors.RED}  Path not found.{Colors.RESET}")
                continue

        # Number selection
        try:
            n = int(choice)
        except ValueError:
            print(f"{Colors.RED}  Invalid selection.{Colors.RESET}")
            continue

        if n == 0:
            current = current.parent
            continue

        all_items = dirs + files
        if 1 <= n <= len(all_items):
            selected = all_items[n - 1]
            if selected.is_dir():
                current = selected
            else:
                return str(selected)
        else:
            print(f"{Colors.RED}  Number out of range.{Colors.RESET}")


def _terminal_save_picker(title: str, ext: str) -> Optional[str]:
    from ixoryn.ui.banner import Colors
    print(f"\n{Colors.CYAN}  [Save File] {title}{Colors.RESET}")
    path = input(f"  Enter output file path (e.g., output{ext}): ").strip()
    if not path:
        return None
    if not path.endswith(ext):
        path += ext
    return path


def _terminal_dir_picker(title: str) -> Optional[str]:
    from ixoryn.ui.banner import Colors
    print(f"\n{Colors.CYAN}  [Select Directory] {title}{Colors.RESET}")
    path = input("  Enter directory path: ").strip()
    if path and os.path.isdir(path):
        return path
    return None


def _human_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

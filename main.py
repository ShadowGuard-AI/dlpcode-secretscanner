#!/usr/bin/env python3

import argparse
import logging
import re
import os
import sys
from pygments import highlight
from pygments.lexers import get_lexer_for_filename, guess_lexer
from pygments.formatters import Terminal256Formatter

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define regular expressions for common secrets
# The API Key pattern has no word boundaries, so a token longer than
# 45 characters matches in 45 character pieces and one real key can
# be reported several times at shifting offsets.
PATTERNS = {
    "API Key": r"[a-zA-Z0-9]{32,45}",  # Example: Long alphanumeric string
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    # The secret key entry starts with the same AKIA shape as the ID
    # entry and then asks for 40 key characters after a line break.
    # A bare secret key on its own line, with no access key ID above
    # it, never matches this pattern at all.
    "AWS Secret Access Key": r"AKIA[0-9A-Z]{16}.*?[\r\n].*?[a-zA-Z0-9/+=]{40}",
    "Secret Key": r"sk-[a-zA-Z0-9]{48}",
    "Password": r"(password|pwd|pass)\s*[:=]\s*['\"]?[\w\d@#$%^&*()_+{}\[\]:;<>,.?\/~\\-]{6,}['\"]?",
}


# Compiled once at import. scan_file used to hand the raw strings to
# finditer for every file in a tree, recompiling the same five patterns
# (behind the re module cache, but still per file bookkeeping).
COMPILED_PATTERNS = {name: re.compile(pat, re.MULTILINE | re.IGNORECASE) for name, pat in PATTERNS.items()}


def mask_secret(value):
    """
    Redacts a matched secret for display, keeping its length visible.

    The scanner exists to find secrets; printing each one in full, right
    under the file it was found in, turns the terminal output and any
    captured log of it into a second copy of the leak. The first and last
    few characters stay visible so a finding can still be matched against
    the source line by eye.
    """
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans code for accidentally committed secrets.")
    parser.add_argument("path", help="Path to the file or directory to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-e", "--exclude", help="Comma-separated list of file extensions to exclude (e.g., .txt,.log).", default="")
    return parser


def scan_file(file_path, exclude_extensions):
    """
    Scans a single file for secrets using predefined patterns.

    Args:
        file_path (str): The path to the file to scan.
        exclude_extensions (list): A list of file extensions to exclude.

    Returns:
        list: A list of dictionaries, each representing a detected secret.
    """
    # Compare the real suffix, lowercased. A plain endswith matched files
    # whose names merely ended in the letters (a file called "scrappy"
    # against ".py" style entries never matched, but "notes.TXT" slipped
    # past a ".txt" exclusion), so case decided whether a file was scanned.
    suffix = os.path.splitext(file_path)[1].lower()
    if suffix in {ext.lower() for ext in exclude_extensions}:
        logging.debug(f"Skipping file due to extension: {file_path}")
        return [], False

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError as e:
        logging.warning(f"Could not decode file {file_path}: {e}")
        return [], True
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return [], True

    secrets = []
    for name, pattern in COMPILED_PATTERNS.items():
        try:
            matches = pattern.finditer(content)
            for match in matches:
                secret = {
                    "file": file_path,
                    "name": name,
                    "match": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                }
                secrets.append(secret)
        except re.error as e:
            logging.error(f"Regex error for pattern '{name}': {e}")

    return secrets, False


def scan_directory(dir_path, exclude_extensions):
    """
    Recursively scans a directory for secrets.

    Args:
        dir_path (str): The path to the directory to scan.
        exclude_extensions (list): A list of file extensions to exclude.

    Returns:
        list: A list of dictionaries, each representing a detected secret.
    """
    secrets = []
    unreadable = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            found, failed = scan_file(file_path, exclude_extensions)
            secrets.extend(found)
            if failed:
                unreadable.append(file_path)
    return secrets, unreadable


def highlight_code(file_path, secret):
    """
    Highlights the code snippet containing the secret using Pygments.

    Args:
        file_path (str): The path to the file containing the secret.
        secret (dict): A dictionary containing information about the secret.

    Returns:
        str: The highlighted code snippet, or an empty string if an error occurs.
    """
    try:
        # The file is read again here for every single finding, so a
        # file with twenty matches is opened and read twenty times
        # before the report finishes. Correct, just not cheap.
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        try:
            lexer = get_lexer_for_filename(file_path)
        except Exception:
            try:
                lexer = guess_lexer(content)
            except Exception:
                lexer = None

        snippet_start = max(0, secret["start"] - 100)
        snippet_end = min(len(content), secret["end"] + 100)
        snippet = content[snippet_start:snippet_end]
        # Redact every pattern match inside the snippet, not only the
        # finding that produced it. A nearby secret inside the context
        # window would otherwise be printed in full, which is the leak
        # the Match line mask was added to stop.
        for pattern in COMPILED_PATTERNS.values():
            snippet = pattern.sub(lambda m: mask_secret(m.group(0)), snippet)

        if lexer:
            formatter = Terminal256Formatter(style='fruity')  # Choose a style
            highlighted_code = highlight(snippet, lexer, formatter)
            return highlighted_code
        else:
            return f"No lexer found for {file_path}.  Plain text snippet:\n{snippet}"
    except Exception as e:
        logging.error(f"Error highlighting code for {file_path}: {e}")
        return ""


def main():
    """
    Main function to parse arguments and initiate the scanning process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    path = args.path
    exclude_extensions = [ext.strip() for ext in args.exclude.split(",") if ext.strip()]

    if not os.path.exists(path):
        logging.error(f"Path does not exist: {path}")
        sys.exit(1)

    unreadable = []
    if os.path.isfile(path):
        logging.info(f"Scanning file: {path}")
        secrets, failed = scan_file(path, exclude_extensions)
        if failed:
            unreadable.append(path)
    elif os.path.isdir(path):
        logging.info(f"Scanning directory: {path}")
        secrets, unreadable = scan_directory(path, exclude_extensions)
    else:
        logging.error(f"Invalid path: {path}. Must be a file or directory.")
        sys.exit(1)

    if secrets:
        print("Potential secrets found:")
        for secret in secrets:
            print(f"  File: {secret['file']}")
            print(f"  Type: {secret['name']}")
            print(f"  Match: {mask_secret(secret['match'])}")
            highlighted_code = highlight_code(secret["file"], secret)
            if highlighted_code:
                print("  Code Snippet:\n")
                print(highlighted_code)
            print("-" * 40)
    elif not unreadable:
        print("No secrets found.")

    if unreadable:
        print(f"Scan incomplete: could not read {len(unreadable)} file(s): {', '.join(unreadable)}")
        logging.error(f"Scan incomplete: could not read {len(unreadable)} file(s).")
        sys.exit(1)

if __name__ == "__main__":
    main()
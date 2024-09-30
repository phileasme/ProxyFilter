"""
proxy_file_manager.py

This module provides utility functions for managing proxy files, including reading,
writing, and parsing proxy information. It handles various file operations and
proxy string manipulations required for the proxy filtering system.

Functions:
    - write_proxies_to_file: Write a list of proxies to a file.
    - append_proxies_to_file: Append a list of proxies to a file.
    - parse_proxy_string: Parse a proxy string into its components.
    - check_historical_proxies: Load historical proxies from files.
    - read_proxy_list: Read a list of proxies from a file.
    - convert: Convert a list of tuples into a dictionary.
"""
import os
import logging
from typing import Set, List, Tuple, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def write_proxies_to_file(proxies, file_path):
    """
    Write a list of proxies to a file, creating the file and its directory if they don't exist.

    Args:
        proxies (List[str]): List of proxy strings to write.
        file_path (str): Path to the file where proxies will be written.

    Raises:
        IOError: If there's an error writing to the file.
    """
    try:
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Write the proxies to the file
        with open(file_path, 'w') as f:
            for proxy in proxies:
                f.write(f"{proxy.strip()}\n")
        logging.info(f"Wrote {len(proxies)} proxies to {file_path}")
    except IOError as e:
        logging.error(f"Error writing to file {file_path}: {e}")

# You might also want to update the append_proxies_to_file function similarly:

def append_proxies_to_file(proxies, file_path):
    """
    Append a list of proxies to a file, creating the file and its directory if they don't exist.

    Args:
        proxies (List[str]): List of proxy strings to append.
        file_path (str): Path to the file where proxies will be appended.

    Raises:
        IOError: If there's an error appending to the file.
    """
    try:
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Append the proxies to the file
        with open(file_path, 'a') as f:
            for proxy in proxies:
                f.write(f"{proxy.strip()}\n")
        logging.info(f"Appended {len(proxies)} proxies to {file_path}")
    except IOError as e:
        logging.error(f"Error appending to file {file_path}: {e}")

def parse_proxy_string(proxy_string: str) -> Tuple[str, str, int, Set[str], int]:
    """
    Parse a proxy string into its components.

    Args:
        proxy_string (str): The proxy string to parse.

    Returns:
        Tuple[str, str, int, Set[str], int]: A tuple containing:
            - IP address (str)
            - Port number (str)
            - Validity status (int)
            - Set of providers (Set[str])
            - Number of calls (int)
    """
    proxy_string_split = proxy_string.split(":")
    ip, port_info = proxy_string_split[0], proxy_string_split[1] if len(proxy_string_split) > 1 else ""
    port, validity, providers, calls = port_info, -1, set(), 0

    if "|" in port_info:
        port, additional_info = port_info.split("|", 1)
        if "~" in additional_info:
            validity_str, providers_calls = additional_info.split("~")
            validity = int(validity_str)
            if "+" in providers_calls:
                providers_str, calls_str = providers_calls.split("+")
                providers = set(filter(None, providers_str.split(",")))
                calls = int(calls_str)
            else:
                providers = set(filter(None, providers_calls.split(",")))
        else:
            validity = int(additional_info) if additional_info.isdigit() else -1

    return ip, port, validity, providers, calls

def check_historical_proxies():
    """
    Check and load historical proxies from files.

    Returns:
        Dict[str, List[str]]: A dictionary containing historical proxy data,
        where keys are file types and values are lists of proxy strings.
    """
    historical_proxies = {}
    for file in ["historical", "working", "broken", "untested"]:
        proxies = read_proxy_list(f"{file}_proxies", "proxy/proxies")
        historical_proxies[file] = proxies
    for file in ["unroutable", "cloudflare", "routable"]:
        addresses = read_proxy_list(f"{file}_addresses", "proxy/proxies")
        historical_proxies[file] = addresses
    return historical_proxies


def read_proxy_list(kind=None, folder="proxies"):
    """
    Read a list of proxies from a file.
    
    Args:
        kind (str, optional): Proxy file name type. Defaults to None.
        folder (str): Folder where proxy files are stored. Defaults to 'proxies'.
    
    Returns:
        List[str]: A list of proxies read from the specified file.

    Raises:
        FileNotFoundError: If the specified file is not found.
        IOError: If there's an error reading the file.
    """
    # Normalize `kind` to be a list
    if isinstance(kind, str):
        kind = [kind]
    elif kind is None:
        kind = ["broken_proxies", "working_proxies", "historical_proxies"]

    file_path = os.path.join(folder, f"_{kind[0]}.txt")
    proxies = []
    
    try:
        with open(file_path, "r") as f:
            proxies = [x.strip().lower() for x in f if x.strip()]  # Read and clean up lines
    except FileNotFoundError:
        logging.warning(f"File not found: {file_path}")
    except IOError as e:
        logging.error(f"Error reading file {file_path}: {e}")
    
    return proxies

# Removed the duplicate write_proxies_to_file function as it's already defined above

def convert(tup: list, di: dict) -> dict:
    """Convert a list of tuples into a dictionary."""
    for a, b in tup:
        di.setdefault(a, []).append(b)
    return di

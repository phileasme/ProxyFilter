import socket
import ipaddress
import subprocess
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import List, Dict, Set

logger = logging.getLogger(__name__)

class Routability:
    """
    A class to check the routability of IP addresses.

    This class provides methods to validate IP addresses, check if they are routable,
    and handle special cases like Cloudflare IPs.
    """

    def __init__(self):
        self.routable_addresses: Set[str] = set()
        self.invalid_addresses: Set[str] = set()
        self.cloudflare_addresses: Set[str] = set()

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Check if the given string is a valid IP address.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP is valid, False otherwise.
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if the given IP address is private.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP is private, False otherwise.
        """
        return ipaddress.ip_address(ip).is_private

    @staticmethod
    def ping_ip(ip: str, count: int = 1, timeout: int = 2) -> bool:
        """
        Ping an IP address to check if it's reachable.

        Args:
            ip (str): The IP address to ping.
            count (int): Number of ping attempts (default: 1).
            timeout (int): Timeout for each ping attempt in seconds (default: 2).

        Returns:
            bool: True if the ping was successful, False otherwise.
        """
        try:
            output = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), ip],
                capture_output=True, text=True, timeout=timeout + 1
            )
            return output.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    @staticmethod
    def traceroute_ip(ip: str, max_hops: int = 30, timeout: int = 3) -> bool:
        """
        Perform a traceroute to an IP address to check its routability.

        Args:
            ip (str): The IP address to traceroute.
            max_hops (int): Maximum number of hops (default: 3).
            timeout (int): Timeout for each hop in seconds (default: 2).

        Returns:
            bool: True if the IP address appears at least twice in the traceroute output, False otherwise.
        """
        os_type = platform.system()
        try:
            if os_type == "Darwin":  # macOS
                traceroute_command = [
                    "traceroute", "-m", str(max_hops), "-w", str(timeout), ip
                ]
            else:  # Linux and others
                traceroute_command = [
                    "traceroute", "-T", "-m", str(max_hops), "-w", str(timeout), ip
                ]

            result = subprocess.run(
                traceroute_command,
                capture_output=True, text=True, timeout=timeout * max_hops
            )
            
            # Count occurrences of the IP in the output
            ip_occurrences = result.stdout.count(ip)
            print(f"ip occurences, {ip_occurrences}, {result.stdout}")
            # Consider successful if IP appears at least twice
            return ip_occurrences >= 2

        except subprocess.TimeoutExpired:
            logger.warning(f"Traceroute timed out for IP: {ip}")
            return False
        except Exception as e:
            logger.error(f"Error during traceroute for {ip}: {e}")
            return False

    @staticmethod
    def is_cloudflare(ip: str) -> bool:
        """
        Check if an IP address is associated with Cloudflare.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP is associated with Cloudflare, False otherwise.
        """
        try:
            response = requests.get(f"http://{ip}", timeout=2)
            return 'cloudflare' in response.headers.get('Server', '').lower()
        except requests.RequestException:
            return False

    def is_routable(self, ip: str) -> bool:
        """
        Check if an IP address is routable.

        This method performs several checks:
        1. Validates the IP address format
        2. Checks if it's a private IP
        3. Checks if it's associated with Cloudflare
        4. Pings the IP
        5. Performs a traceroute

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP is routable, False otherwise.
        """
        if not self.is_valid_ip(ip) or self.is_private_ip(ip):
            return False

        if self.is_cloudflare(ip):
            logger.debug(f"{ip} is associated with Cloudflare")
            self.cloudflare_addresses.add(ip)
            return False

        is_pingable = self.ping_ip(ip)  # ICMP
        if not is_pingable:
            return False
        
        is_traceable = self.traceroute_ip(ip)  # TCP & TTL check
        return is_traceable

    def validate_ip_list(self, ip_list: List[str], max_workers: int = 200) -> Dict[str, bool]:
        """
        Validate a list of IP addresses for routability.

        This method uses a ThreadPoolExecutor to check multiple IPs concurrently.

        Args:
            ip_list (List[str]): List of IP addresses to validate.
            max_workers (int): Maximum number of concurrent workers (default: 200).

        Returns:
            Dict[str, bool]: A dictionary with IP addresses as keys and their routability as values.
        """
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.is_routable, ip): ip for ip in ip_list}
            
            with tqdm(total=len(ip_list), desc="Validating IPs") as pbar:
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        is_routable = future.result()
                        results[ip] = is_routable
                        if is_routable:
                            self.routable_addresses.add(ip)
                        elif ip not in self.cloudflare_addresses:
                            self.invalid_addresses.add(ip)
                    except Exception as exc:
                        logger.error(f"{ip} generated an exception: {exc}")
                        results[ip] = False
                        self.invalid_addresses.add(ip)
                    finally:
                        pbar.update(1)
        
        return results

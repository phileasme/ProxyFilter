import socket
import ipaddress
import subprocess
import requests
import logging
import platform  # Add this import
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Set, List, Dict, Optional
from tqdm import tqdm
from functools import lru_cache
import subprocess
logger = logging.getLogger(__name__)

class Routability:
    """
    A class to check the routability of IP addresses.

    This class provides methods to validate IP addresses, check if they are routable,
    and handle special cases like Cloudflare IPs.
    """

    def __init__(self, max_checks_per_subnet: int = 3):
        self.routable_addresses: Set[str] = set()
        self.invalid_addresses: Set[str] = set()
        self.cloudflare_addresses: Set[str] = set()
        self.subnet_check_count: Dict[str, int] = defaultdict(int)
        self.max_checks_per_subnet = max_checks_per_subnet
        self.subnet_cache: Dict[str, bool] = {}

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

    @lru_cache(maxsize=1000)
    def get_subnet(self, ip: str) -> Optional[str]:
        """
        Get the subnet for an IP address with caching.

        Args:
            ip (str): The IP address.

        Returns:
            Optional[str]: The subnet in CIDR notation, or None if invalid.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return self._get_local_subnet(ip)
            else:
                return self._get_public_subnet(ip)
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return None


    def _get_local_subnet(self, ip: str) -> str:
        try:
            # For Linux/Unix systems
            output = subprocess.check_output(["ip", "route", "get", ip]).decode()
            subnet = output.split("src")[1].strip().split()[0]
            return subnet
        except Exception:
            try:
                # For Windows systems
                output = subprocess.check_output(["route", "print", ip]).decode()
                subnet = output.split("\n")[7].split()[2]
                return subnet
            except Exception:
                # Fallback to default subnets for private IPs
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_loopback:
                    return str(ipaddress.ip_network(f"{ip}/8", strict=False))
                elif ip_obj.packed[0] == 10:  # 10.0.0.0/8
                    return str(ipaddress.ip_network(f"{ip}/8", strict=False))
                elif ip_obj.packed[0] == 172 and 16 <= ip_obj.packed[1] <= 31:  # 172.16.0.0/12
                    return str(ipaddress.ip_network(f"{ip}/12", strict=False))
                elif ip_obj.packed[0] == 192 and ip_obj.packed[1] == 168:  # 192.168.0.0/16
                    return str(ipaddress.ip_network(f"{ip}/16", strict=False))
                return str(ipaddress.ip_network(f"{ip}/24", strict=False))

    async def _get_public_subnet(self, ip: str) -> str:
        """
        Asynchronously query WHOIS database for public IP subnet information.

        Args:
            ip (str): The IP address.

        Returns:
            str: The subnet in CIDR notation.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        for network in data.get('networks', []):
                            cidr = network.get('cidr')
                            if cidr:
                                return cidr
            # If WHOIS query fails, use a conservative estimate
            return str(ipaddress.ip_network(f"{ip}/{self.subnet_mask}", strict=False))
        except asyncio.TimeoutError:
            logger.warning(f"Timeout querying subnet for {ip}")
        except Exception as e:
            logger.error(f"Error querying subnet for {ip}: {str(e)}")
        # Fallback to conservative estimate
        return str(ipaddress.ip_network(f"{ip}/{self.subnet_mask}", strict=False))

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
        subnet = self.get_subnet(ip)
        
        # Check if we've already determined routability for this subnet
        if subnet in self.subnet_cache:
            return self.subnet_cache[subnet]
        
        # Check if we've exceeded the maximum checks for this subnet
        if self.subnet_check_count[subnet] >= self.max_checks_per_subnet:
            return False  # Assume not routable if we've exceeded checks
        
        self.subnet_check_count[subnet] += 1
        
        if not self.is_valid_ip(ip) or self.is_private_ip(ip):
            return False

        if self.is_cloudflare(ip):
            logger.debug(f"{ip} is associated with Cloudflare")
            self.cloudflare_addresses.add(ip)
            return False

        is_pingable = self.ping_ip(ip)
        if not is_pingable:
            return False
        
        is_traceable = self.traceroute_ip(ip)
        
        # Cache the result for this subnet
        self.subnet_cache[subnet] = is_traceable
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

from collections import defaultdict, OrderedDict
from typing import Set, List, Dict
from dataclasses import dataclass, field
from proxy.routability import Routability
from proxy.proxy_file_manager import parse_proxy_string, check_historical_proxies, write_proxies_to_file
import aiohttp, asyncio
from tqdm.asyncio import tqdm
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class ProxyFilter:
    @dataclass
    class PortInfo:
        validity: int = -1
        providers: Set[str] = field(default_factory=set)
        calls: int = 0

        def update(self, validity: int = -1, providers: Set[str] = None, calls: int = 0):
            if validity != -1:
                self.validity = validity
            if providers:
                self.providers.update(providers)
            self.calls += calls

    def __init__(self):
        self.ips: Dict[str, Dict] = defaultdict(
            lambda: {"ports": OrderedDict(), "routable": False, "cloudflare": False}
        )
        self.routable_addresses: Set[str] = set()
        self.unroutable_addresses: Set[str] = set()
        self.cloudflare_addresses: Set[str] = set()
        self.cloudflare_proxies: Set[str] = set()
        self.untested_proxies: Set[str] = set()
        self.working_proxies: Set[str] = set()

    def update_ip_entry(self, ip: str, port: str, validity: int, providers: Set[str], calls: int, is_routable: bool, is_cloudflare: bool):
        if ip not in self.ips:
            self.ips[ip] = {"ports": OrderedDict(), "routable": False, "cloudflare": False}

        self.ips[ip]["routable"] = is_routable
        self.ips[ip]["cloudflare"] = is_cloudflare
        
        if port not in self.ips[ip]["ports"]:
            self.ips[ip]["ports"][port] = self.PortInfo()
        
        self.ips[ip]["ports"][port].update(validity=validity, providers=providers, calls=calls)

    async def process_proxies(self, proxies: List[str] = [], historical: bool = False, reprocess_historical: bool = False, test_proxies: bool = False):
        if historical or reprocess_historical:
            await self.handle_historical_classes(reprocess_historical)
        
        if proxies:
            await self.process_new_proxies(proxies)
        
        if test_proxies:
            await self.test_and_update_proxies()

        if self.ips:
            self.update_proxy_files()


    async def handle_historical_classes(self, reprocess: bool = False):
        logging.info("==== Historical Load ====")
        historical_proxies_by_class = check_historical_proxies()

        if reprocess:
            logging.info("Reprocessing historical data...")
            # Clear existing data
            self.ips.clear()
            self.routable_addresses.clear()
            self.unroutable_addresses.clear()
            self.cloudflare_addresses.clear()

            # Combine all historical proxies for reprocessing
            all_proxies = []
            for proxies in historical_proxies_by_class.values():
                all_proxies.extend(proxies)

            # Reprocess all proxies
            await self.process_proxy_list(all_proxies, "historical")
        else:
            # Process historical data without revalidation
            for file_type, proxies in historical_proxies_by_class.items():
                for proxy in proxies:
                    ip, port, validity, providers, calls = parse_proxy_string(proxy)

                    is_routable = file_type in ["routable", "working", "untested"]
                    is_cloudflare = file_type == "cloudflare"

                    if validity == -1:
                        if file_type == "working":
                            validity = 1
                            self.working_proxies.add(f"{ip}:{port}")
                        elif file_type in ["broken", "unroutable"]: #would add cloudflare here if its a constraint
                            validity = 0
                        else:
                            self.untested_proxies.add(f"{ip}:{port}")

                    self.update_ip_entry(ip, port, validity, providers, calls, is_routable, is_cloudflare)

                    if file_type == "unroutable":
                        self.unroutable_addresses.add(ip)
                    elif file_type == "cloudflare":
                        self.cloudflare_addresses.add(ip)
                        self.cloudflare_proxies.add(f"{ip}:{port}")
                    elif file_type in ["routable", "working", "untested"]:
                        self.routable_addresses.add(ip)

        logging.info(f"Historical Load Complete. Processed {sum(len(proxies) for proxies in historical_proxies_by_class.values())} proxies.")



    def update_proxy_files(self):
        print("==== Updating proxy files ====")
        new_proxies = {
            "untested": set(),
            "working": set(),
            "broken": set(),
            "unroutable": self.unroutable_addresses,
            "cloudflare": self.cloudflare_addresses,
            "routable": self.routable_addresses,
        }

        for ip, document in self.ips.items():
            for port, port_info in document["ports"].items():
                validity = port_info.validity
                providers = ",".join(sorted(port_info.providers)) if port_info.providers else ""
                calls = port_info.calls

                proxy = f"{ip}:{port}|{validity}~{providers}"
                if calls > 0:
                    proxy += f"+{calls}"

                if validity == -1:
                    new_proxies["untested"].add(proxy)
                    self.untested_proxies.add(f"{ip}:{proxy})")
                elif validity == 0:
                    new_proxies["broken"].add(proxy)
                elif validity == 1:
                    new_proxies["working"].add(proxy)
                    self.working_proxies.add(f"{ip}:{proxy})")
                else:
                    logging.warning(f"Unknown validity state for {proxy}: {validity}")

        self.update_file_contents(new_proxies)

    async def process_new_proxies(self, proxies: List[str]):
        print("=== New Address ===")
        await self.process_proxy_list(proxies, "new")

    def update_file_contents(self, new_proxies: Dict[str, Set[str]]):
        for file_type, proxies in new_proxies.items():
            if file_type in {"unroutable", "routable", "cloudflare"}:
                file_path = f"proxy/proxies/_{file_type}_addresses.txt"
            else:
                file_path = f"proxy/proxies/_{file_type}_proxies.txt"

            existing_proxies = self.read_proxy_list(file_type)
            updated_proxies = self.merge_proxies(existing_proxies, proxies)

            if updated_proxies:
                write_proxies_to_file(list(updated_proxies), file_path)
                logging.info(f"Updated {file_type}.txt: {len(updated_proxies)} total proxies")
            else:
                logging.info(f"No proxies to write for {file_path}")

    @staticmethod
    def merge_proxies(existing_proxies: List[str], new_proxies: Set[str]) -> Set[str]:
        merged = {}
        for proxy_set in (existing_proxies, new_proxies):
            for proxy in proxy_set:
                ip, port, validity, providers, calls = parse_proxy_string(proxy)
                ip_port = f"{ip}:{port}"
                
                if ip_port not in merged:
                    merged[ip_port] = [validity, providers, calls]
                else:
                    # Keep the most recent validity (non-negative values take precedence)
                    if validity >= 0:
                        merged[ip_port][0] = validity
                    # Merge providers
                    merged[ip_port][1].update(providers)
                    # Add calls
                    merged[ip_port][2] += calls

        # Construct the merged proxy strings
        return {
            f"{ip_port}|{validity}~{','.join(sorted(providers))}+{calls}" 
            if calls > 0 and (validity != -1 or providers)
            else (f"{ip_port}|{validity}" if validity != -1 else ip_port)
            for ip_port, (validity, providers, calls) in merged.items()
        }


    @staticmethod
    def extract_ip(proxy: str) -> str:
        """Extract the IP address from a proxy string."""
        return proxy.split(':')[0]

    async def process_proxy_list(self, proxies: List[str], proxy_type: str):
        test_addresses = set(self.extract_ip(address) for address in proxies if address)
        seen_address = defaultdict(list)
        for x in test_addresses:
            if x in self.unroutable_addresses:
                seen_address["unroutable"].append(x)
            elif x in self.routable_addresses:
                seen_address["routable"].append(x)
            else:
                seen_address["unknown"].append(x)

        logger.info(f"Already seen stats unrouted: {len(seen_address['unroutable'])}, routed: {len(seen_address['routable'])}, unknown {len(seen_address['unknown'])}")
        addresses_only = list(set(test_addresses) - self.unroutable_addresses - self.cloudflare_addresses - self.routable_addresses)
        logger.info(f"{proxy_type} group being tested with {len(addresses_only)} addresses")

        if "unroutable" not in proxy_type:
            checker = Routability()
            checker.validate_ip_list(addresses_only)
            logger.info("Done Validating")
            
            logger.debug(f"Before update - Routable: {len(self.routable_addresses)}, Unroutable: {len(self.unroutable_addresses)}, Cloudflare: {len(self.cloudflare_addresses)}")
            logger.debug(f"Checker results - Routable: {len(checker.routable_addresses)}, Invalid: {len(checker.invalid_addresses)}, Cloudflare: {len(checker.cloudflare_addresses)}")
            
            self.routable_addresses.update(checker.routable_addresses)
            self.unroutable_addresses.update(checker.invalid_addresses)
            self.cloudflare_addresses.update(checker.cloudflare_addresses)
            
            logger.debug(f"After update - Routable: {len(self.routable_addresses)}, Unroutable: {len(self.unroutable_addresses)}, Cloudflare: {len(self.cloudflare_addresses)}")

        self.update_ip_info(proxies, proxy_type, checker.routable_addresses, checker.cloudflare_addresses)

    def update_ip_info(self, proxies: List[str], proxy_type: str, routable_addresses: Set[str], cloudflare_addresses: Set[str]):
        logger.debug(f"Updating IP info for {len(proxies)} proxies")
        for proxy in proxies:
            ip, port, validity, providers, calls = parse_proxy_string(proxy)

            is_routable = ip in routable_addresses
            is_cloudflare = ip in cloudflare_addresses

            self.cloudflare_proxies.add(f"{ip}:{port}")

            if "unroutable" in proxy_type or "broken" in proxy_type: #add cloudlfare if its an issue is_cloudflare
                validity = 0
            elif "working" in proxy_type:
                validity = 1

            logger.debug(f"Updating IP entry: {ip}:{port} - Routable: {is_routable}, Cloudflare: {is_cloudflare}, Validity: {validity}")
            self.update_ip_entry(ip, port, validity, providers, calls, is_routable, is_cloudflare)
        logger.info(f"Done Upading ip info")
    def update_proxy_files(self):
        print("==== Updating proxy files ====")
        new_proxies = {
            "untested": set(),
            "working": set(),
            "broken": set(),
            "unroutable": set(),
            "cloudflare": set(),
            "routable": set(),
        }

        for ip, document in self.ips.items():
            if document["cloudflare"]:
                new_proxies["cloudflare"].add(ip)
                # continue
            if not document["routable"]:
                new_proxies["unroutable"].add(ip)
                continue
            new_proxies["routable"].add(ip)

            # Could use refinement here.
            for port, port_info in document["ports"].items():
                validity = port_info.validity
                providers = ",".join(sorted(port_info.providers)) if port_info.providers else ""
                calls = port_info.calls

                proxy = f"{ip}:{port}|{validity}~{providers}"
                if calls > 0:
                    proxy += f"+{calls}"

                if validity == -1:
                    new_proxies["untested"].add(proxy)
                elif validity == 0:
                    new_proxies["broken"].add(proxy)
                elif validity == 1:
                    new_proxies["working"].add(proxy)
                else:
                    logging.warning(f"Unknown validity state for {proxy}: {validity}")

        self.update_file_contents(new_proxies)

    @staticmethod
    def read_proxy_list(file_type):
        if file_type in {"unroutable", "routable", "cloudflare"}:
            file_path = f"proxy/proxies/_{file_type}_addresses.txt"
        else:
            file_path = f"proxy/proxies/_{file_type}_proxies.txt"
        
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.warning(f"File not found: {file_path}")
            return []
        except IOError as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return []
        
    @staticmethod
    async def test_single_proxy(session: aiohttp.ClientSession, proxy: str, timeout: int = 10) -> bool:
        """
        Test a single proxy by making an async HTTP request.
        
        :param session: aiohttp ClientSession
        :param proxy: Proxy string in format "ip:port"
        :param timeout: Timeout in seconds
        :return: True if the proxy works, False otherwise
        """
        try:
            url = "http://httpbin.org/ip"  # We'll use this to test our proxy
            proxy_url = f"http://{proxy}"
            async with session.get(url, proxy=proxy_url, timeout=timeout) as response:
                if response.status == 200:
                    return True
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            logging.debug(f"Proxy {proxy} failed: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error testing proxy {proxy}: {str(e)}")
        return False
    
    @staticmethod
    async def proxy_calls(proxies: List[str], timeout: int = 10, max_concurrent: int = 1000) -> Dict[str, bool]:
        """
        Test multiple proxies concurrently with a progress bar.
        
        :param proxies: List of proxy strings in format "ip:port"
        :param timeout: Timeout for each request in seconds
        :param max_concurrent: Maximum number of concurrent requests
        :return: Dictionary mapping each proxy to its working status
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_with_semaphore(proxy: str):
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    results[proxy] = await ProxyFilter.test_single_proxy(session, proxy, timeout)

        tasks = [test_with_semaphore(proxy) for proxy in proxies]
        
        # Use tqdm with asyncio
        for _ in tqdm.as_completed(tasks, total=len(tasks), desc="Testing proxies"):
            await _
        
        return results

    async def test_and_update_proxies(self):
        test_set = set()
        for ip, data in self.ips.items():
            if data.unroutable:
                continue
            max_ports = 3
            for port in data['ports']:
                if max_ports == 0:
                    break
                test_set.add(f"{ip}:{port}")
                max_ports =- 1
        
        logging.info(f"Starting to test {len(test_set)} proxies...")
        results = await self.proxy_calls(list(test_set))
        
        self.untested_proxies.clear()
        
        for proxy, is_working in results.items():
            ip, port = proxy.split(':')
            is_cloudflare = self.ips[ip]["cloudflare"] if ip in self.ips else False
            if is_working:
                self.update_ip_entry(ip, port, validity=1, providers=set(), calls=1, is_routable=True, is_cloudflare=is_cloudflare)
                self.working_proxies.add(proxy)
                self.routable_addresses.add(ip)
            else:
                self.update_ip_entry(ip, port, validity=0, providers=set(), calls=1, is_routable=True, is_cloudflare=is_cloudflare)
                self.working_proxies.discard(proxy)
                if not any(ip in p for p in self.working_proxies):
                    self.routable_addresses.discard(ip)
        
        for ip, data in self.ips.items():
            for port, port_info in data['ports'].items():
                if port_info.validity == -1:
                    self.untested_proxies.add(f"{ip}:{port}")
        
        logging.info(f"Tested {len(results)} proxies. Working: {sum(results.values())}, Not working: {len(results) - sum(results.values())}")
        logging.info(f"Remaining untested proxies: {len(self.untested_proxies)}")

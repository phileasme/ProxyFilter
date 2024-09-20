# Proxy Validation System

## Overview

This project is a simple but robust proxy filtering system designed to manage, test, and categorize proxy servers. It provides functionality to process both new and historical proxy data, test proxy connectivity, and maintain organized lists of proxies based on their status and performance. 

### Motive
Proxy reliability is a critical issue in network operations. Surprisingly, many proxies provided by various services are not even routable IP addresses, which can lead to numerous issues. This tool is particularly valuable for projects that rely on dynamic proxy pools, such as:
- Custom rotation services
- Proxies from unconventional or diverse sources
- Frequently changing proxy lists

By using this tool, you can mitigate the risks associated with unreliable proxies. Making requests through non-functional proxies can have serious consequences:
- Your IP address and services may be flagged and potentially suspended by your hosting provider.
- Failed connection attempts might be misinterpreted as malicious activity:
    - They can resemble Distributed Denial of Service (DDoS) attacks
    - Or be mistaken for port scanning attempts

These issues often result in automated systems or network administrators reporting your traffic as potential network abuse. By validating proxies before use, you can significantly reduce these risks and improve the overall reliability and safety of your proxy-dependent operations.

## Features

**We check if the address is:**
>-    private
>-    behind Cloudflare
>-    reachability: ICMP, TCP.
>-    tunnelable (optionally)

**Tasks involved:**
>- Process and categorize proxy servers
>- Test proxy connectivity asynchronously
>- Handle historical proxy data
>- Maintain lists of routable, unroutable, and Cloudflare addresses
>- File-based storage for proxy lists
>- Concurrent proxy testing with progress tracking

## Usage

To use the proxy filtering system, you can import the `ProxyFilter` class from the main module and use its methods. Here's a basic example:

```python
from proxy.proxyfilter import ProxyFilter

async def main():
    proxy_filter = ProxyFilter()
    # Add and process new potential proxies
    # Acceptable formats are as so, where everything passed the port is optional:
    # "8.8.8.8:80|1~provider1,provider2+5"  <--> "<ip>:<port>|<validity>~<*providers>+<calls>" <--> 
    new_proxies = ["1.1.1.1:80", "2.2.2.2:8080"]
    await proxy_filter.process_proxies(proxies=new_proxies, historical=True, test_proxies=True)

    proxy_filter = ProxyFilter()
    # Load historical proxies and test them
    await proxy_filter.process_proxies(historical=True, test_proxies=True)
    
    proxy_filter = ProxyFilter()
    # Load historical proxies and test them
    await proxy_filter.process_proxies(reprocess_historical=True)

    # feature_flags:
    #   historical: if files in proxies are existant, we will use their information to avoid reprocessing already 
    #   test_proxies: tunnels through the proxies and makes a simple http request, if functional the proxy is validated.

    # While files will be generated in proxy/proxies, the relevant information will be also accessible after processing in:

    #                                                 Port{port number, validity status, providers, number of calls}
    proxy_filter.ips #: Dict[str, Dict](lambda: {"ports": OrderedDict(Port), "routable": False, "cloudflare": False})
    proxy_filter.routable_addresses # 212.252.72.106
    proxy_filter.unroutable_addresses # 3.87.195.240
    proxy_filter.cloudflare_addresses # 1.1.1.1
    proxy_filter.untested_proxies # 67.43.236.20:28545
    proxy_filter.working_proxies # 212.252.72.106:3128|1~bigprovider,smallguy,unreliablelist+3
    
    
    # The results will be saved in the respective files in the 'proxy/proxies/' directory

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## Project Structure

- `proxy/`
  - `proxyfilter.py`: Main ProxyFilter class implementation
  - `routability.py`: Handles IP routability checks
  - `proxy_file_manager.py`: Manages file operations for proxy lists
- `tests/`: Contains unit tests for the project
- `main.py`: Example script to run the proxy filtering system
- `requirements.txt`: List of Python dependencies

## Configuration
This is optional, they will be generated provided candidate proxy addresses.
The system uses several configuration files located in the `proxy/proxies/` directory:
- `_working_proxies.txt`: List of working proxies
- `_broken_proxies.txt`: List of non-working proxies
- `_untested_proxies.txt`: List of proxies that haven't been tested yet
- `_routable_addresses.txt`: List of routable IP addresses
- `_unroutable_addresses.txt`: List of unroutable IP addresses
- `_cloudflare_addresses.txt`: List of Cloudflare IP addresses

## Contributing

Contributions to this project are welcome. Please follow these steps to contribute:

1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to your branch
5. Create a new Pull Request

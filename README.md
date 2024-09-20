# Proxy Validation System

## Overview

This project is a robust proxy filtering/validation system designed to manage, test, and categorize proxy servers. It provides functionality to process both new and historical proxy data, test proxy connectivity, and maintain organized lists of proxies based on their status and performance. Often times proxies given by different providers are not even routable ip addresses.

We test each address for:
- It's format
- If it is private
- If it is behind Cloudflare
- It's reachability: ICMP, TCP
- Optionaly, if we can tunnel an http request through it

## Features

- Process and categorize proxy servers
- Test proxy connectivity asynchronously
- Handle historical proxy data
- Maintain lists of routable, unroutable, and Cloudflare addresses
- File-based storage for proxy lists
- Concurrent proxy testing with progress tracking

## Usage

To use the proxy filtering system, you can import the `ProxyFilter` class from the main module and use its methods. Here's a basic example:

```python
from proxy.proxyfilter import ProxyFilter

async def main():
    proxy_filter = ProxyFilter()
    
    # Process historical proxies and test them
    await proxy_filter.process_proxies(historical=True, test_proxies=True)
    
    # Add and process new potential proxies
    # Acceptable formats are as so, where everything passed the port is optional:
    # "8.8.8.8:80|1~provider1,provider2+5"  <--> "<ip>:<port>|<validity>~<*providers>+<calls>" <--> 
    new_proxies = ["1.1.1.1:80", "2.2.2.2:8080"]
    await proxy_filter.process_proxies(proxies=new_proxies, historical=True, test_proxies=True)
    # feature_flags:
    #   historical: if files in proxies are existant, we will use their information to avoid reprocessing already 
    #   test_proxies: tunnels through the proxies and makes a simple http request, if functional the proxy is validated.

    # While files will be generated in proxy/proxies, the relevant information will be also accessible after processing in:
    proxy_filter.ips #: Dict[str, Dict](lambda: {"ports": OrderedDict(), "routable": False, "cloudflare": False})
    proxy_filter.routable_addresses
    proxy_filter.unroutable_addresses
    proxy_filter.cloudflare_addresses
    proxy_filter.untested_proxies
    proxy_filter.working_proxies
    
    
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

from proxy.proxy_filter import ProxyFilter
from proxy.extractor import ProxyExtractor
import asyncio


async def main():
  
    proxy_filter = ProxyFilter()
    extractor = ProxyExtractor()

    await extractor.fetch_and_extract()
    
    # Print the results
    proxies = [ proxy for proxy, providers in extractor.proxy_to_providers.items()]
    
    await proxy_filter.process_proxies(proxies, historical=True, test_proxies=True)

    # Get next proxy
    next_proxy = proxy_filter.get_next_proxy()
    if next_proxy:
        print(f"Next proxy to use: {next_proxy}")
    
    # Test and update proxies
    await proxy_filter.test_and_update_proxies()


if __name__ == "__main__":
    asyncio.run(main())
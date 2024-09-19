from proxy.proxyfilter import ProxyFilter
import asyncio


async def main():
  
    proxy_filter = ProxyFilter()
    proxies = [
        # ...
    ]
    await proxy_filter.process_proxies(proxies, historical=True, test_proxies=True)


if __name__ == "__main__":
    asyncio.run(main())
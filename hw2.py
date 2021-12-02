import asyncio
from aiohttp import web
import config
import handler


async def main():
    server = web.Server(handler.handler)
    runner = web.ServerRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', config.port, shutdown_timeout=config.timeout)
    await site.start()

    print(f"======= Serving on {site.name} ======")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    try:
        future = asyncio.ensure_future(main())
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    loop.close()

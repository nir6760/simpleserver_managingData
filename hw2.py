import asyncio
from aiohttp import web
import config
import os
import json
import handler


def load_json_mime():
    current_dir = os.getcwd()
    json_path = os.path.join(current_dir, 'mime.json')
    with open(json_path) as json_file:
        dict = json.load(json_file)
    return dict

mimeDict = load_json_mime()


async def main():
    server = web.Server(handler.handler)
    runner = web.ServerRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', config.port, shutdown_timeout=config.timeout)
    await site.start()

    print(f"======= Serving on {site.name} ======")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(main())
    loop.run_forever()

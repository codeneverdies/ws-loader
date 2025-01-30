import os
import argparse
import asyncio as aio
import aiohttp as atp
import aiofiles as afi
from aiohttp import web

ws_srv = argparse.ArgumentParser(prog='ws-server')
ws_srv.add_argument('-i', required=True, type=str, help='IP')
ws_srv.add_argument('-p', required=True, type=int, help='Port')
ws_srv.add_argument('-b', required=True, type=str, help='Path to binary')
args = ws_srv.parse_args()

class ws_server:

    """
    Websocket server to send binaries over a websocket connection
    """

    def __init__( self, home: str, port: int, binfile: str ):

        self.home = home
        self.port = port
        self.bin = binfile

        self.app    = web.Application()
        self.route  = self.app.router
        self.__init_routes()

        self.headers: dict = {}
        self.headers["Server"] = "Nginx" # I really don't know..

    def __init_routes(self):
        self.route.add_get("/", self.root)
        self.route.add_get("/ws", self.ws_handler)

    async def run(self):

        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.home, self.port)
        await site.start()

        print(f"Running -> {self.home}:{self.port}")

    async def root(self, request):
        # Better to return nothing?
        return web.Response(body="Go away!\n", content_type="text/plain", headers=self.headers)

    async def ws_handler(self, request):

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        print("[!] Websocket connection")

        # Send size of binary

        file_sz_str = str(os.path.getsize(self.bin))
        file_sz_int = int(file_sz_str)

        print(f"[+] Size of {self.bin}:{file_sz_str}")

        await ws.send_str(file_sz_str)

        async with afi.open(self.bin, mode="rb") as f:
            while file_sz_int > 0:
                try:
                    data = await f.read(2048)
                    await ws.send_bytes(data)
                    file_sz_int -= 2048
                except:
                    break

        print(f"[+] Sent {self.bin}")

        # Close the connnection

        await ws.close()
        return ws

async def main():

    srv = ws_server(args.i, args.p, args.b)
    await srv.run()

    while True:
        await aio.sleep(0.5)

if __name__ == "__main__":
    try:
        aio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")
        exit(-1)

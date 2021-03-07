import json
import logging
import time

import pandas as pd
from websocket_server import WebsocketServer

PORT = 9999
HOST = "0.0.0.0"
LOG_LEVEL = logging.DEBUG


class WebSocketServerNew(object):
    def __init__(self, host: str, port: str):
        self.server = WebsocketServer(port, host)

    def start(self):
        self.server.set_fn_new_client(self.new_client)
        self.server.run_forever()

    def new_client(self, client, server):
        print("new client")
        print(client)
        self.server.send_message(client, "hellow client")

        df = pd.read_csv("systems_recently.csv")

        header = df.columns
        data = []
        idx = 0
        for item in df.itertuples():
            d = {key: value for key, value in zip(header, item)}

            if idx < 5:
                data.append(d)
                idx += 1
            else:
                self.server.send_message(client, json.dumps(data))
                idx = 0


if __name__ == "__main__":
    server = WebSocketServerNew(HOST, PORT)
    server.start()

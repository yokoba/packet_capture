import websocket

PORT = 9999
HOST = "192.168.0.252"


class WebsocketClientNew(object):
    def __init__(self, host: str, port: str):
        self.client = websocket.WebSocketApp(f"ws://{HOST}:{PORT}", on_message=self.on_message)

        try:
            websocket.enableTrace(True)
            self.client.run_forever()
        except KeyboardInterrupt:
            self.client.close()

    def on_open(self, ws):
        print(ws)

    def on_message(self, wsapp, message):
        print(message)


if __name__ == "__main__":
    client = WebsocketClientNew(HOST, PORT)

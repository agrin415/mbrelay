#!/usr/bin/env python

# modbus relay unix domain socket control client
# a command-line client for external control of the modbus relay process via a
# UNIX domain socket

# created 2018-02-27 agrinberg
# modified 2018-02-28 agrinberg

import json
import select
import socket
import struct
import sys
import threading
import time

server_address = 'mymodbus.sock'

class UDSClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connected = False

    def _handle_disconnect(self):
        self.connected = False
        print('\nsocket closed!')
        self._stop()
        exit(1)

    def _stop(self):
        self.sock.shutdown(2)
        self.sock.close()
        self.prompt_thread.join(0)

    def _recv(self):
        data = self.sock.recv(4)
        if not data:
            return
        data_len = struct.unpack('L', data)[0]
        data = self.sock.recv(data_len)
        if not data:
            return
        return data

    def _prompt(self):
        while self.connected:
            message = raw_input(self.name + ' CONTROL> ')
            if not self.connected:
                return
            message = message[:256]

            if message:
                self.sock.send(message)
                data = self._recv()
                if not data:
                    return
                response = json.loads(data)
                status = response[0]
                payload = response[1]

                if isinstance(payload, list):
                    for item in payload:
                        print(str(item))
                    continue

                if isinstance(payload, dict):
                    for key, value in payload.iteritems():
                        print('{:<16} : {:>2}'.format(key, str(value)))
                    continue

                parsed_response = ''
                if status == 1:
                    parsed_response = 'error: '
                parsed_response += str(payload)
                print(parsed_response)

    def connect(self):
        try:
            self.sock.connect(server_address)
        except socket.error, msg:
            print >>sys.stderr, msg
            sys.exit(1)
        self.connected = True

    def run(self):
        self.sock.send('name')
        name_data = self._recv()
        if not name_data:
            self._handle_disconnect()
        self.name = json.loads(name_data)[1]

        self.prompt_thread = threading.Thread(target=self._prompt)
        self.prompt_thread.daemon = True
        self.prompt_thread.start()

        while self.connected:
            try:
                ready_r, ready_w, err = select.select([self.sock,],
                                                    [self.sock,], [], 1)
            except select.error:
                self._handle_disconnect()

            if len(ready_r) > 0:
                self._handle_disconnect()
            time.sleep(0.1)

        self.connected = False
        self._stop()
        exit(0)

def main():
    client = UDSClient()
    client.connect()
    try:
        client.run()
    except KeyboardInterrupt:
        print('')
        exit(0)

if __name__ == '__main__':
    main()

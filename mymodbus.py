#!/usr/bin/env python

# this is my replacement for the non-operational modbus proxy originally for
# (the now defunct) map.pqube.com.

# This is a caching reverse proxy that can funnel large numbers of client
# connections for a large number of pqubes while caching register data so the
# pqubes aren't overwhelmed with requests.

# The entire thing runs in a single process, with each pqube having its own
# dedicated thread running a single event loop handling multiple clients for
# that pqube

# created 2018-01-24 agrinberg
# modified 2018-02-28 agrinberg

import argparse
import json
import os
import Queue
import select
import socket
import struct
import sys
import time
from threading import Thread, Event

# import the pqube configuration dictionary from map.pqube.com's pqubes.py
from pqubes import pqubes

MYNAME = 'ModbusRelay'

BIND_ADDR = str(socket.INADDR_ANY) # bind to whatever ipv4 address is available
TIMEOUT = 10 # seconds to wait for socket time out
WAIT_TIME = 15 # seconds to wait for threads to start
MAX_BACKLOG = 256 # maximum backlog of connections to listen for per port
RECV_BYTES = 256 # number of bytes to receive on sockets

# settings for unix domain socket for IPC/control from outside process
DEFAULT_CONTROL_UDS = 'mymodbus.sock'
CONTROL_UDS = DEFAULT_CONTROL_UDS
CONTROL_RECV_BYTES = 256

EUID = 65534 # effective user id to run server as. 65534 is normally nobody
EGID = EUID # effective group id to run server as

VERBOSE = False
QUIET = False
DEFAULT_DEBUG_LEVEL = 0
DEBUG_LEVEL = DEFAULT_DEBUG_LEVEL

CACHE = False # controls if caching is enabled. off by default
DEFAULT_CACHE_TIME = 0.5
CACHE_TIME = DEFAULT_CACHE_TIME # time in seconds cached data will be served

# modbus packet structure information - this probably shouldn't change
MBREQ = struct.Struct('>HHHBBHH')
MBREP = struct.Struct('>HHHBBB')

# helper function to elevate privileges
def elevate_privileges(uid=0, gid=0):
    os.seteuid(uid)
    os.setegid(gid)

# helper function to drop privileges
def drop_privileges(uid=EUID, gid=EGID):
    os.setegid(gid)
    os.seteuid(uid)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='verbose output',
                        action='store_true')
    parser.add_argument('-c', '--cache', help='enable caching',
                        action='store_true')
    parser.add_argument('-cT', '--cache-time', help='set cache time',
                        default=DEFAULT_CACHE_TIME, type=float)
    parser.add_argument('-s', '--socket',
                        help='set path to unix domain socket for ipc',
                        default=DEFAULT_CONTROL_UDS)
    parser.add_argument('-q', '--quiet', help='suppress normal output',
                        action='store_true')
    parser.add_argument('-d', '--debug-level',
                        help='debug level (higher number = more info)',
                        default=DEFAULT_DEBUG_LEVEL, type=int)
    return parser.parse_args()

def print_msg(msg, prefix='[+] '):
    # since we're printing messages from threads, I use sys.stdout.write()
    # instead of print() because it behaves better
    sys.stdout.write(prefix + msg + '\n')
    sys.stdout.flush()

def error(msg):
    sys.stderr.write('error: ' + msg + '\n')
    sys.stderr.flush()
    sys.stdout.flush()

# for regular output
def rmsg(msg):
    if not QUIET:
        print_msg(msg)

# for verbose output
def vmsg(msg):
    if VERBOSE:
        print_msg(msg, '[V] ')

# for debug output. they have different levels so you can control how much info
# gets printed. you pass the level in dmsg() to determine what level it has to
# be set to get printed. default level is 1 if parameter is omitted
def dmsg(msg, level=1):
    if DEBUG_LEVEL >= level:
        print_msg(msg, '[D] ')

# just a little helper function for parsing peer name tuples to strings
def parse_peer_name(peer_name):
    parsed_name = peer_name[0] + ':' + str(peer_name[1])
    return parsed_name

# helper function for generating debug output on network traffic
def net_debug(peer1, peer2, data, direction):
    traffic = ' ' + direction + ' ' + repr(data) + ' ' + direction + ' '
    return peer1 + traffic + peer2

# a class to represent binary data
class Data:
    def __init__(self, raw_data=None):
        if raw_data:
            self.data = raw_data

    def __repr__(self):
        return repr(self.data)

    def __str__(self):
        return str(self.data)

    def __iter__(self):
        return iter(str(self))

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)

    def __getitem__(self, items):
        return self.data[items]

    def __len__(self):
        return len(self.data)

    def pack(self, data_tuple):
        self.data = struct.pack(str(len(data_tuple)) + 'B', *data_tuple)
        return self.data

    def unpack(self):
        return struct.unpack(str(len(self.data)) + 'B', str(self.data))

# a class to represent a client connection
class Client:
    def __init__(self, proxy, sock):
        self.sock = sock
        self.name = parse_peer_name(sock.getpeername())
        self.bracket_name = '[' + self.name + ']'
        self.proxy = proxy
        # add self to proxy's clients dict by the socket
        self.proxy.clients[self.sock] = self
        self.sock.setblocking(0)
        # add self's socket to proxies inputs list
        self.proxy.inputs.append(self.sock)
        # create message queue and add it to the proxy's message queues list
        self.message_queue = Queue.Queue()
        self.proxy.message_queues[self.sock] = self.message_queue

    def disconnect(self):
        # remove client socket from proxy's outputs and inputs
        if self.sock in self.proxy.outputs:
            self.proxy.outputs.remove(self.sock)
        if self.sock in self.proxy.inputs:
            self.proxy.inputs.remove(self.sock)

        # then we close the socket
        self.sock.close()

        # remove them from proxy's message queues
        if self.sock in self.proxy.message_queues:
            del self.proxy.message_queues[self.sock]

        # and finally remove the client from the proxy's client dictionary
        if self.sock in self.proxy.clients:
            del self.proxy.clients[self.sock]

    def recv(self, numbytes=RECV_BYTES):
        if not self.proxy.pqube.connected:
            # no sense keeping them connected if the pqube is down
            msg = 'not connected to pqube. disconnecting client '
            rmsg(msg + self.name + ' on port: ' + self.proxy.lport)
            self.disconnect()

        try:
            data = self.sock.recv(numbytes)
        except:
            # if the recv() call fails, we set data to none to indicate problem
            data = None
        if data:
            # push client's request into message queue
            self.message_queue.put(data)

            # if they're not already in the outputs list, add them to it
            if self.sock not in self.proxy.outputs:
                self.proxy.outputs.append(self.sock)

            return data

        else:
            # if we failed to receive data, we disconnect the client
            dcmsg = 'closing connection for ' + self.name
            rmsg(dcmsg + ' on port ' + self.proxy.lport)
            self.disconnect()

    def send(self, data):
        try:
            self.sock.send(data)
            dmsg(net_debug(self.bracket_name, self.proxy.name, data, '<-'), 2)
        except socket.error:
            # if we cant send data to the client, they're disconnected
            error(self.name + ' disconnected! cannot send data.')
            # handle it gracefully
            self.disconnect()
        dmsg('', 2)

# a class to represent modbus request packet
class MBRequest:
    def __init__(self, data):
        self.raw_data = data
        # first 9 bytes contain the header
        self.header = Data(data[0:9])
        # everything from the 9th byte to the end of the packet is the payload
        self.data = Data(data[9:len(data)])
        # the register number is found in the 5th item of the unpacked payload
        self.unpacked_data = MBREQ.unpack(data)
        self.register = self.unpacked_data[5]
        # number of registers data requested from including initial register
        self.count = self.unpacked_data[6]

# a class to represent modbus response packet
class MBResponse:
    def __init__(self, data, header=False):
        if header:
            self.data = Data(data[MBREP.size:])
        else:
            self.data = Data(data)
        self.payload_size = len(self.data)

    def forge(self, request):
        # get disassembled header from request and put it in a mutable list
        header_data = list(request.header.unpack())

        # the 8th byte must contain the length of the payload
        header_data[8] = self.payload_size

        # the 5th byte must contain the length of the payload plus 3
        header_data[5] = self.payload_size + 3

        # reassemble this modified request header to send with the response
        new_header = Data()
        new_header.pack(tuple(header_data))
        # append the cached response data to the modified header and return it
        return new_header + self.data

# a class to represent the register cache
class Cache:
    def __init__(self):
        # just a dictionary of register number:cached data object
        self.register_cache = {}

    def get(self, request):
        if not CACHE:
            return

        # for the number of registers requested from the starting register in
        # the request packet, we fetch the cached data for each of them, then
        # we assemble them into a single response payload and forge a new
        # response packet using the header from the request
        payloads = ()
        for i in xrange(request.count):
            register = request.register + i
            try:
                cached_data = self.register_cache[register]
                # check if data is stale
                data_age = time.time() - cached_data.timestamp
                if data_age >= CACHE_TIME:
                    return
            except KeyError:
                # return if any of the data is not cached or stale
                # if the get() call returns nothing, the proxy will re-request
                # all the requested registers fresh from the pqube instead.
                # this could be changed to return a list of the missing/stale
                # registers so that only those can be re-requested by the proxy
                # but that might be overdoing it.
                return
            payload = cached_data.response.data.unpack()
            payloads += payload
            dmsg('cache get [' + str(register) + '] = ' + str(payload), 3)

        data = Data()
        data.pack(payloads)
        response = MBResponse(data)
        return response.forge(request)

    def put(self, request, response):
        if not CACHE:
            return

        # we break down the number of registers that were requested from the
        # starting register, divide the response payload into sets of 2 since
        # each register holds 2 bytes, and put each of them into the register
        # dictionary in sequential order
        x = 0
        unpacked_response = response.data.unpack()
        for i in xrange(request.count):
            register = request.register + i
            payload = unpacked_response[x:x+2]
            dmsg('cache put [' + str(register) + '] = ' + str(payload), 3)
            data = Data()
            data.pack(payload)
            saved_response = MBResponse(data)
            self.register_cache[register] = CachedData(saved_response)
            x += 2

# a class to represent cached data
class CachedData:
    def __init__(self, response):
        self.response = response
        self.timestamp = time.time()

# a class to represent an individual pqube
class PQube:
    def __init__(self, host, remote_port, local_port, name=None):
        self.name = name # name is optional, its just nice to know
        self.host = host
        self.remote_port = remote_port # modbus port on pqube
        self.short_name = self.host + ':' + str(self.remote_port)
        self.local_port = local_port # port proxy will bind to for this pqube
        self.addr = (host, remote_port)
        self.connected = False
        self.pinging = False
        self.is_alive = False

    def _send_and_recv(self, data, numbytes=RECV_BYTES):
        # attempt to send data up the socket and receive a response from it
        try:
            self.sock.send(data)
            response = self.sock.recv(numbytes)
        except socket.error:
            error(self.short_name + ' error sending/receiving data on socket!')
            # return nothing to indicate a problem sending/receiving
            return
        # otherwise return the response
        return response

    def get_info(self):
        info = {'port': self.local_port}
        if self.name:
            info['name'] = self.name
        return info

    def connect(self, reconnect=False):
        if self.connected and not reconnect:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(TIMEOUT)
        action = 'connecting to pqube: '
        if reconnect:
            action = 're' + action
        port = str(self.remote_port)
        vmsg(action + self.host + ' on port ' + port + '...')
        self.sock.connect(self.addr)
        vmsg('connected to ' + self.host + ' on port ' + port)
        self.connected = True
        self.outgoing_name = parse_peer_name(self.sock.getsockname())
        self.outgoing_name = '[' + self.outgoing_name + ']'
        return self.sock

    def ping(self):
        vmsg('pinging pqube: ' + self.short_name)
        self.pinging = True
        try:
            self.connect()
        except (socket.error, socket.timeout) as e:
            self.pinging = False
            self.is_alive = False
            return False
        self.pinging = False
        self.disconnect()
        self.is_alive = True
        return True

    def disconnect(self):
        try:
            self.sock.close()
        except:
            # if close() fails, the socket's already dead
            pass
        self.connected = False

    def send(self, data):
        response = self._send_and_recv(data)
        if not response:
            # empty response means the pqube disconnected us or there was a
            # problem with _send_and_recv
            errmsg = 'got empty response. disconnecting from pqube: '
            error(errmsg + self.short_name)
            self.disconnect()
        else:
            return response

# modbus proxy server for a single pqube
class Server:
    def __init__(self, pqube, run_event):
        self.run_event = run_event # run event is controlled from relay class
        self.pqube = pqube
        self.host = self.pqube.host
        self.port = str(self.pqube.remote_port)
        self.lport = str(self.pqube.local_port)
        self.clients = {} # keep track of connected clients in this dictionary
        self.server_address = (BIND_ADDR, self.pqube.local_port)
        self.name = '[' + BIND_ADDR + ':' + self.lport + ']'
        self.running = False # keep track of proxy runtime status here
        self.info = self.lport + ' for ' + self.pqube.short_name
        self.cache = Cache() # register data cache

    def _disconnect_clients(self):
        for s in list(self.clients):
            client = self.clients[s]
            msg = 'disconnecting client: ' + client.name
            rmsg(msg + ' on port ' + self.lport)
            client.disconnect()

    def _send_to_pqube(self, data):
        response = self.pqube.send(data)
        if not response:
            # disconnect all clients if pqube is not responding
            rmsg('disconnecting all clients for: ' + self.pqube.short_name)
            self._disconnect_clients()
        else:
            return response

    def _handle_new_client(self, sock):
        if not self.running:
            # in case method gets called after stop() gets called on the thread
            return
        try:
            connection, client_address = sock.accept()
            client = Client(self, connection)
        except socket.error:
            if self.running:
                # only report an error if stop() hasnt been called on thread
                error('failed to accept socket on port: ' + self.info)
            return
        rmsg('new connection from ' + client.name + ' on port ' + self.lport)
        try:
            # this method will return if we're already connected to the pqube
            self.pqube.connect()
        except (socket.error, socket.timeout) as e:
            errmsg = 'failed to connect to pqube: '
            error(errmsg + self.host + ' on port ' + self.port)
            # disconnect the client if we can't connect to the pqube
            dcmsg = 'disconnecting client: ' + client.name
            rmsg(dcmsg  + ' on port ' + self.lport)
            client.disconnect()

    def _handle_cheeky_client(self, client, data):
        if 'fuck you' in data:
            client.send('fuck you too, pal!\n')

    def _handle_incoming_data(self, sock, data):
        client = self.clients[sock]
        dmsg(net_debug(client.bracket_name, self.name, data, '->'), 2)
        try:
            request = MBRequest(data)
            dmsg(' ' * 24 + str(request.unpacked_data), 2)
        except:
            errmsg = client.name + ' sent malformed request: ' + repr(data)
            error(errmsg + '. disconnecting...')
            self._handle_cheeky_client(client, data) # lol
            client.disconnect()
            try:
                req_data = Data(data)
                unpacked_req = req_data.unpack()
                dmsg(client.bracket_name + ':' + str(unpacked_req))
            except:
                pass
            return
        # see if we have register data in cache
        forged_response = self.cache.get(request)
        if forged_response:
            response = Data(forged_response)
            # send cached register data back to client if present
            dmsg(' ' * 24 + str(response.unpack()), 2)
            client.send(response.data)
            return

        # if we don't have a cached response, get a fresh one from the pqube
        pqube = '[' + self.pqube.short_name + ']'
        dmsg(self.name + ' sending data to pqube...', 4)
        raw_response = self._send_to_pqube(data)
        dmsg(net_debug(self.pqube.outgoing_name, pqube, data, '->'), 2)
        if raw_response:
            msg = net_debug(self.pqube.outgoing_name, pqube, raw_response, '<-')
            dmsg(msg, 2)
            # if we got a response from the pqube, cache it
            try:
                response = MBResponse(raw_response, header=True)
                self.cache.put(request, response)
                dmsg(' ' * 24 + str(response.data.unpack()), 2)
            except:
                errmsg = pqube + ' sent malformed response: '
                errmsg += repr(raw_response)
                error(errmsg + '. Cannot cache!')
                try:
                    response_data = Data(raw_response)
                    unpacked_response = data.unpack()
                    dmsg(client.bracket_name + ':' + str(request.unpacked_data))
                    dmsg(pqube + ':' + str(unpacked_response))
                except:
                    pass

            # try to send it back to client
            client.send(raw_response)

    def _relay(self, sock):
        try:
            # check the message queue to see if there's any new data
            dmsg(self.name + ' checking message_queue...', 4)
            next_msg = self.message_queues[sock].get_nowait()
            dmsg(self.name + ' got next_msg', 4)
        except Queue.Empty:
            # if the queue is empty, we remove the socket from the output list
            dmsg(self.name + ' message queue is empty!', 4)
            if sock in self.outputs:
                self.outputs.remove(sock)
        except KeyError:
            # if this happens the socket was removed from message queue
            dmsg(self.name + ' got KeyError checking queue!')
            # no need to panic
            pass
        else:
            # we got some new data from the client
            self._handle_incoming_data(sock, next_msg)

    def _handle_exceptional(self, sock):
        # this is for handling exceptional conditions
        # haven't actually seen this called yet, but its here just in case
        try:
            peer = parse_peer_name(sock.getpeername())
        except:
            if sock in self.clients:
                client = self.clients[sock]
                peer = client.name
            else:
                peer = '[unknown]'

        vmsg(self.name + ' handling exceptional condition for ' + peer)

        if sock in self.clients:
            client = self.clients[sock]
            client.disconnect()
            return

        if sock == self.pqube.sock:
            self.pqube.disconnect()

        if sock in self.inputs:
            self.inputs.remove(sock)
        if sock in self.outputs:
            self.outputs.remove(sock)
        try:
            sock.close()
        except:
            pass

        del self.message_queues[sock]

    def _recv(self):
        # this is the main event loop for the proxy
        dmsg(self.name + ' starting event loop...')

        # keep going until inputs=empty, running=False or run_event is cleared
        while self.inputs and self.running and self.run_event.is_set():
            dmsg(self.name + ' calling select.select()...', 4)
            # check to see if any of these file descriptors have data buffered
            # the select call will unblock after 1 second if we got nothing
            try:
                readable, writable, exceptional = select.select(self.inputs,
                                                                self.outputs,
                                                                self.inputs, 1)
            except select.error as ex:
                if ex[0] == 4:
                    continue
                else:
                    raise

            dmsg(self.name + ' checking readable list', 4)
            for s in readable:
                # if there's any items in the readable list, that means 1 or
                # more sockets in self.inputs has incoming data buffered

                # if the socket is our incoming_sock, someone just connected
                if s is self.incoming_sock:
                    # handle incoming client connection
                    self._handle_new_client(s)

                # if its another socket, its data coming from a client socket
                else:
                    # handle incoming data from client
                    client = self.clients[s]
                    client.recv()

            # if we have connected clients
            if self.clients:
                dmsg(self.name + ' checking writable list', 4)
                # check if we have any data to send them
                for s in writable:
                    # if there's any items in the writable list, that means 1
                    # or more sockets in self.outputs has outgoing data

                    # relay the data
                    self._relay(s)

                dmsg(self.name + ' checking exceptional list', 4)
                for s in exceptional:
                    # handle exceptional condition
                    self._handle_exceptional(s)

            if not self.clients and self.pqube.connected:
                # if we dont have any clients and we're connected to the pqube
                if not self.pqube.pinging:
                    # if we're not pinging the pqubes to check their status
                    msg = 'no clients connected, disconnecting from pqube: '
                    vmsg(msg + self.pqube.short_name)
                    # disconnect from it
                    self.pqube.disconnect()

            # technically, other work could be done in this loop after the
            # select.select() call unblocks, but we're not doing that now

        # if the loop is broken, run_event was cleared or proxy.stop() called
        if self.running:
            # if we're not running, that means stop() already got called
            self.stop() # we only call it if it hasn't been called already

    def start(self):
        if self.running:
            rmsg('proxy is already running on port: ' + self.info)
            return
        rmsg('starting proxy on port: ' + self.info)
        self.incoming_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.incoming_sock.setblocking(0)
        self.incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


        # bind to the port
        try:
            self.incoming_sock.bind(self.server_address)
        except socket.error as ex:
            if ex[0] == 98:
                error('could not bind to port: ' + self.info + '. port in use')
                return
            else:
                raise

        # listen for connections
        self.incoming_sock.listen(MAX_BACKLOG)

        # add our newly bound socket to the inputs list
        self.inputs = [self.incoming_sock]

        # initialize our outputs and message queue lists
        self.outputs = []
        self.message_queues = {}

        # we are now running!
        self.running = True
        # start the main event loop for this proxy instance
        self._recv()

    def stop(self):
        if not self.running:
            rmsg('proxy is not running on port: ' + self.info)
            return
        # we set running to False to indicate stop() has been called
        self.running = False

        # disconnect every client on this proxy if there are any
        self._disconnect_clients()
        if self.pqube.connected:
            # disconnect from the pqube if connected to it
            vmsg('disconnecting from pqube: ' + self.pqube.short_name)
            self.pqube.disconnect()
        rmsg('stopping proxy on port: ' + self.info)
        try:
            # try to shutdown the socket
            self.incoming_sock.shutdown(socket.SHUT_RDWR)
        except:
            # if it fails, there's nothing to shut down. no need to worry
            pass
        # close the socket
        self.incoming_sock.close()

        # once clients are disconnected, only incoming sock remains in inputs
        if self.incoming_sock in self.inputs:
            # the _recv() loop will end when self.inputs is empty
            self.inputs.remove(self.incoming_sock)
            # and since we set running=False it knows not to call stop() again

# class to represent control client connected to control server
class ControlClient:
    def __init__(self, sock, address):
        self.sock = sock
        self.address = address
        self.connected = True

    def disconnect(self):
        self.sock.close()
        self.connected = False

    def send(self, data):
        try:
            self.sock.send(data)
            dmsg('sent data to control client: ' + repr(data))
        except socket.error as ex:
            if ex[0] == 32:
                error('failed to send response to control client.')
                return
            else:
                raise

    def recv(self, numbytes=CONTROL_RECV_BYTES):
        try:
            data = self.sock.recv(numbytes)
        except socket.error as ex:
            if ex[0] == 104:
                error('control socket connection reset by client')
                return
            else:
                raise

        if data:
            dmsg('received data from control client: ' + data)
            return data
        else:
            vmsg('no more data from control client: ' + self.address)
            return

class ControlResponse:
    def __init__(self, status, data):
        json_data = json.dumps((status, data))
        json_len = len(json_data)
        l = struct.pack('L', json_len)
        self.data = l + json_data

# a server that provides an interface to control the relay from other processes
class ControlServer:
    def __init__(self, relay):
        self.relay = relay
        self.commands = [
            ('add', self._cmd_add),
            ('remove', self._cmd_remove),
            ('list', self._cmd_list),
            ('test', self._cmd_test),
            ('name', self._cmd_name),
            ('help', self._cmd_help),
            ('exit', self._cmd_disconnect)
        ]
        self.help = {
            'add'   : ('add a pqube to the relay and start a proxy for it',
                        'add HOST REMOTE_PORT LOCAL_PORT [NAME]'),
            'remove': ('remove a pqube from the relay and stop its proxy',
                        'remove LOCAL_PORT'),
            'list'  : ('get a list of pqubes',
                        'list [all|alive|dead]'),
            'test'  : ('a command for testing the control server',
                        'test [list|dict|str|int]'),
            'name'  : ('get the name of the relay',),
            'help'  : ('show command list or usage for individual commands',
                        'help [command]'),
            'exit'  : ('disconnect from the control server',)
        }

    def _handle_incoming(self, data):
        argv = data.split(' ')
        for command, callback in self.commands:
            if argv[0] == command:
                callback(argv[1:])
                return

        response = ControlResponse(1, 'unrecognized command')
        self.client.send(response.data)

    def _cmd_help(self, args):
        if not args:
            commands = []
            for tup in self.commands:
                commands.append(tup[0])
            response = ControlResponse(0, 'commands: ' + ', '.join(commands))
            self.client.send(response.data)
            return
        else:
            arg = args[0]

        if arg in self.help:
            description = self.help[arg][0]
            try:
                usage = self.help[arg][1]
            except IndexError:
                usage = None
            help_text = description
            if usage:
                help_text += '\nusage: ' + usage
            response = ControlResponse(0, help_text)
        else:
            response = ControlResponse(1, 'unrecognized command')
        self.client.send(response.data)

    def _cmd_name(self, args):
        response = ControlResponse(0, MYNAME)
        self.client.send(response.data)

    def _cmd_test(self, args):
        try:
            arg = args[0]
        except IndexError:
            arg = None
        if arg == 'dict':
            data = {'foo': 'bar'}
        elif arg == 'list':
            data = ['foo', 'bar']
        elif arg == 'int':
            data = 123
        else:
            data = 'foo bar'
        response = ControlResponse(0, data)
        self.client.send(response.data)

    def _cmd_list(self, args):
        try:
            arg = args[0]
        except IndexError:
            arg = 'all'

        pqubes = []
        if arg == 'all':
            for pqube in self.relay.pqube_list:
                info = pqube.get_info()
                pqubes.append(info)
        elif arg == 'alive':
            pqubes, dead_pqubes = self.relay.ping_sweep()
        elif arg == 'dead':
            alive_pqubes, pqubes = self.relay.ping_sweep()
        else:
            errmsg = 'invalid argument. usage: ' + self.help['list'][1]
            response = ControlResponse(1, errmsg)
            self.client.send(response.data)
            return

        if not pqubes:
            response = ControlResponse(0, 'no pqubes found')
            self.client.send(response.data)
        else:
            response = ControlResponse(0, pqubes)
            self.client.send(response.data)

    def _cmd_disconnect(self, args):
        self.client.disconnect()

    def _cmd_add(self, args):
        try:
            host = args[0]
            remote_port = int(args[1])
            local_port = int(args[2])
        except (IndexError, ValueError) as ex:
            errmsg = 'invalid arguments. '
            errmsg += 'usage: ' + self.help['add'][1]
            response = ControlResponse(1, errmsg)
            self.client.send(response.data)
            return

        name = ' '.join(args[3:]).strip('"')
        if name == '':
            name = None

        pqube = PQube(host, remote_port, local_port, name)
        proxy = self.relay.add(pqube)
        if not proxy:
            errmsg = 'cannot add pqube. port already in use?'
            response = ControlResponse(1, errmsg)
            self.client.send(response.data)
        else:
            self.relay.start(proxy)
            if proxy.running:
                msg = 'pqube'
                if name:
                    msg += ': ' + name
                msg += ' added. proxy now listening on port ' + str(local_port)
                response = ControlResponse(0, msg)
                self.client.send(response.data)
            else:
                errmsg = 'failed to start proxy on port ' + str(local_port)
                response = ControlResponse(1, errmsg)
                self.client.send(response.data)

    def _cmd_remove(self, args):
        try:
            local_port = int(args[0])
        except IndexError:
            errmsg = 'no port number specified. usage: '
            errmsg += self.help['remove'][1]
            response = ControlResponse(1, errmsg)
            self.client.send(response.data)
            return
        except ValueError:
            response = ControlResponse(1, 'invalid port number')
            self.client.send(response.data)
            return

        if local_port not in self.relay.local_ports:
            msg = 'no pqube found on local port: ' + str(local_port)
            response = ControlResponse(1, msg)
            self.client.send(response.data)
            return

        pqube = self.relay.local_ports[local_port]
        self.relay.remove(pqube)
        msg = 'removed pqube: ' + pqube.short_name + ' on port: ' + args[0]
        response = ControlResponse(0, msg)
        self.client.send(response.data)

    def _recv(self):
        while self.relay.run_event.is_set():
            try:
                connection, client_addr = self.incoming_sock.accept()
                vmsg('incoming connection on control socket: ' + client_addr)
                self.client = ControlClient(connection, client_addr)
            except socket.timeout:
                continue
            while self.client.connected and self.relay.run_event.is_set():
                ready = select.select([connection], [], [], 1)
                if not ready[0]:
                    continue

                data = self.client.recv()
                if not data:
                    break

                self._handle_incoming(data)

            vmsg('closing connection for control client: ' + client_addr)
            self.client.disconnect()

        rmsg('closing control socket...')
        self.incoming_sock.close()
        elevate_privileges()
        try:
            os.unlink(CONTROL_UDS)
        except OSError:
            if os.path.exists(CONTROL_UDS):
                raise
        drop_privileges()

    def start(self):
        # create a unix domain socket for inter-process communication
        self.incoming_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.incoming_sock.settimeout(1)
        rmsg('starting control server on UNIX socket: ' + CONTROL_UDS)
        try:
            elevate_privileges()
            self.incoming_sock.bind(CONTROL_UDS)
            drop_privileges()
        except socket.error as ex:
            drop_privileges()
            if ex[0] == 98:
                errmsg = 'cannot bind to UNIX socket: ' + CONTROL_UDS
                errmsg += ' file already exists.'
                error(errmsg)
                return
            else:
                raise
        self.incoming_sock.listen(1)
        self.thread = Thread(target=self._recv)
        self.thread.start()

class ModbusRelay:
    def __init__(self, pqube_list=[]):
        # run_event is used for signaling all the threads at once
        # the proxy threads' main event loop will continue running while its set
        # once it has been cleared they will all call stop() on themselves
        self.run_event = Event()

        # initialize lists to store pqube, proxy, and thread instances
        self.pqube_list = []
        self.proxies = []
        self.threads = []

        # a dictionary to keep track of which thread belongs to each proxy
        self.proxy_threads = {}

        # a dictionary to keep track of which proxy belongs to each pqube
        self.pqube_proxies = {}

        # keep track of the ports we've binded so we dont have any duplicates
        self.local_ports = {}
        if not pqube_list:
            # if no pqube_list was passed to us, we load it from pqubes.py
            self._load_pqubes_from_file()
        else:
            # otherwise we load the list that got passed to us instead
            self._load_pqubes(pqube_list) # useful for debugging

        # get the proxies ready to start when start() or start_all() gets called
        self._instantiate_proxies()

    def _load_pqubes(self, pqube_list):
        for pqube in pqube_list:
            port_info = str(pqube.remote_port) + ' => ' + str(pqube.local_port)
            pqube_info = pqube.host + ':' + port_info
            if pqube.name:
                pqube_info = pqube.name + ' (' + pqube_info + ')'

            if pqube.local_port in self.local_ports:
                # dont allow a pqube to be loaded if there's already one
                # assigned to the port number. we can only bind to one port per
                # pqube.
                errmsg = 'cannot load pqube: ' + pqube_info
                error(errmsg + ' -- local port already in use.')
            else:
                # if the port isnt already assigned, we're good to go
                self.pqube_list.append(pqube)
                self.local_ports[pqube.local_port] = pqube
                dmsg('loaded pqube: ' + pqube_info)

        rmsg('loaded ' + str(len(self.pqube_list)) + ' pqubes.')
        return self.pqube_list

    def _load_pqubes_from_file(self):
        # parses the pqube configuration dictionary from pqubes.py
        vmsg('loading pqube list...')
        pqube_list = []
        for pqube in pqubes:
            if 'modbus_host' in pqube:
                name = pqube['long name']
                host = pqube['modbus_host'][0]
                remote_port = pqube['modbus_host'][1]
                local_port = pqube['modbus_serve_port']
                pqube_obj = PQube(host, remote_port, local_port, name)
                pqube_list.append(pqube_obj)
        return self._load_pqubes(pqube_list)

    def _instantiate_proxy(self, pqube):
        # instantiate a proxy and add it to the proxies list
        proxy = Server(pqube, self.run_event)
        self.proxies.append(proxy)
        self.pqube_proxies[pqube] = proxy
        return proxy

    def _instantiate_proxies(self):
        # instantiate a proxy for every pqube instance in the pqube_list
        for pqube in self.pqube_list:
            self._instantiate_proxy(pqube)
        return self.proxies

    def ping_sweep(self):
        unknown_pqubes = []
        alive_pqubes = []
        dead_pqubes = []
        for pqube in self.pqube_list:
            if pqube.connected:
                info = pqube.get_info()
                alive_pqubes.append(info)
            else:
                unknown_pqubes.append(pqube)
                thread = Thread(target=pqube.ping)
                thread.start()
        start_time = time.time()
        problem_pqubes = []

        while any(pqube.pinging for pqube in unknown_pqubes):
            if (time.time() - start_time) >= WAIT_TIME:
                for pqube in unknown_pqubes:
                    if pqube.pinging:
                        problem_pqubes.append(pqube.short_name)
                errmsg = 'pqubes '
                if problem_pqubes:
                    errmsg += ', '.join(problem_pqubes)
                errmsg += ' have not responded for ' + str(WAIT_TIME)
                errmsg += ' seconds. breaking out!'
                error(errmsg)
                break
            time.sleep(0.1)

        for pqube in unknown_pqubes:
            info = pqube.get_info()
            if pqube.is_alive:
                alive_pqubes.append(info)
            else:
                dead_pqubes.append(info)

        return alive_pqubes, dead_pqubes

    def add(self, pqube):
        # this method can be used to add a pqube to the relay while its running
        if pqube.local_port in self.local_ports:
            # but only if the local port you assigned to it isnt already in use
            port_info = str(pqube.remote_port) + ' => ' + str(pqube.local_port)
            pqube_info = pqube.host + ':' + port_info
            errmsg = 'cannot add pqube: ' + pqube_info
            error(errmsg + ' -- local port already in use.')
            return

        # create a new proxy instance for the new pqube and add it to the list
        self.local_ports[pqube.local_port] = pqube
        self.pqube_list.append(pqube)
        proxy = self._instantiate_proxy(pqube)
        # return it so you can start() or stop() it as needed
        return proxy

    def remove(self, pqube):
        # this method can be used to remove a pqube from the relay while running
        try:
            proxy = self.pqube_proxies[pqube]
            if proxy.running:
                self.stop(proxy)
            del self.pqube_proxies[pqube]
            self.proxies.remove(proxy)
        except KeyError:
            pass
        del self.local_ports[pqube.local_port]
        self.pqube_list.remove(pqube)

    def start(self, proxy):
        # method for spawning a new thread for an individual proxy
        # use this when adding pqubes while the relay is already running
        if proxy.running:
            error('proxy is already running on port: ' + proxy.info)
            return
        if not self.run_event.is_set():
            # the proxy's event loop won't run if run_event isn't set
            self.run_event.set() # so we set it if its not set

        # create the thread and add it to our thread list/proxy:thread dict
        thread = Thread(target=proxy.start)
        self.proxy_threads[proxy] = thread
        self.threads.append(thread)

        # make sure we're root
        elevate_privileges()

        # start the thread and keep track of the start time
        thread.start()
        start_time = time.time()
        while not proxy.running:
            # block until the thread has started or WAIT_TIME has been exceeded
            # this is to prevent other methods from being called prematurely
            time.sleep(0.1) # small pause so we dont overwhelm the cpu
            if (time.time() - start_time) >= WAIT_TIME:
                msg = 'thread ' + repr(thread) + ' for proxy: ' + proxy.info
                msg += ' has not started for '
                msg += str(WAIT_TIME) + ' seconds. breaking out...'
                error(msg)
                break

        # drop privileges when finished
        drop_privileges()

        return thread

    def stop(self, proxy):
        # tell the proxy to wrap it up...
        proxy.stop()

        # fetches the thread for the proxy and joins it to the main thread
        thread = self.proxy_threads[proxy]
        thread.join() # will block main thread until the thread is dead
        self.threads.remove(thread) # remove dead thread from our thread list

    def start_all(self):
        # starts all proxies in the proxy list
        for proxy in self.proxies:
            # but only if they're not already running
            if not proxy.running:
                # create a thread for the proxy, add it to the list and dict
                thread = Thread(target=proxy.start)
                self.proxy_threads[proxy] = thread
                self.threads.append(thread)

        # make sure run_event is set so the proxy event loops run
        self.run_event.set()

        # make sure we are root
        elevate_privileges()

        for thread in self.threads:
            # if the thread is not already started
            if not thread.isAlive():
                try:
                    # try to start it
                    thread.start()
                except RuntimeError:
                    # if we get a runtime error, the thread cant be started
                    # this generally shouldnt happen but i ran into it once
                    # during testing so I added this here just so the entire
                    # relay doesn't choke because of a single thread failure
                    errmsg = 'failed to start thread: ' + repr(thread)

                    for key in list(self.proxy_threads):
                        if thread == self.proxy_threads[key]:
                            proxy = key
                        else:
                            proxy = None
                    if proxy:
                        errmsg += ' for proxy: ' + proxy.info
                    error(errmsg)

                    # take the thread out of our list/dict and keep going
                    self.threads.remove(thread)
                    del self.proxy_threads[proxy]
                    pass

        # keep track of when we told the threads to start
        start_time = time.time()
        while not all(proxy.running for proxy in self.proxies):
            # block until all threads are running or WAIT_TIME has been exceeded
            time.sleep(0.1) # small pause so we dont overwhelm the cpu
            if (time.time() - start_time) >= WAIT_TIME:
                problem_proxies = []
                for proxy in self.proxies:
                    if not proxy.running:
                        problem_proxies.append(proxy.info)
                msg = 'threads for proxies: ' + ', '.join(problem_proxies)
                msg += ' have not started for '
                msg += str(WAIT_TIME) + ' seconds. breaking out...'
                error(msg)
                break

        # drop privileges when finished
        drop_privileges()

        return self.threads

    def stop_all(self):
        # clearing run_event will cause all proxies to break their event loop
        self.run_event.clear()
        for thread in self.threads:
            try:
                # join the threads to main thread, blocks until they're all done
                thread.join()
            except RuntimeError:
                # if we get a RuntimeError, the thread's already dead
                pass # no need to panic

        self.threads = [] # don't keep references to stopped threads
        self.proxy_threads = {}

def main():
    # parse command-line arguments
    global VERBOSE
    global QUIET
    global DEBUG_LEVEL
    global CACHE
    global CACHE_TIME
    global CONTROL_UDS

    args = parse_args()
    VERBOSE = args.verbose
    QUIET = args.quiet
    DEBUG_LEVEL = args.debug_level
    CACHE = args.cache
    CACHE_TIME = args.cache_time
    CONTROL_UDS = args.socket

    if QUIET and (VERBOSE or DEBUG_LEVEL > 0):
        # we don't tolerate mixed messages!
        error('you cannot combine option "-q" with "-v" or "-d"')
        exit(1)

    if not os.geteuid() == 0:
        error('you must be root to run this program.')
        exit(1)

    # instantiate the relay and start all of its proxies
    relay = ModbusRelay()
    controller = ControlServer(relay)
    relay.start_all()
    controller.start()

    # keep the main thread running until we get a KeyboardInterrupt
    try:
        while True:
            time.sleep(0.1) # small pause to prevent overwhelming the cpu
    except KeyboardInterrupt:
        # if we get a KeyboardInterrupt, stop all the proxies in the relay
        vmsg('got KeyboardInterrupt, attempting to kill threads...')
        relay.stop_all()

    # let the user know we've reached the end of the main thread and exit()
    rmsg('terminating...')
    exit()

if __name__ == '__main__':
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module contains an implementation of the 'ezpt' transport. """

from obfsproxy.transports.base import BaseTransport

from twisted.internet import reactor
from twisted.internet import protocol

import obfsproxy.common.log as logging
log = logging.get_obfslogger()

class EzptProcess(protocol.ProcessProtocol):
    def __init__(self):
        self.stream = None

    def connectionMade(self):
        log.debug("Process started!")

    def set_stream(self, stream):
        log.debug("Setting stream to %s", str(stream))
        self.stream = stream

    def outReceived(self, data):
        log.debug("Received stdout from process: %s", str(data))
        self.stream.write(data)

    def inConnectonLost(self):
        log.debug("inConnectionLost called!")

    def outConnectionLost(self):
        log.debug("outConnectionLost called!")

class EzptTransport(BaseTransport):
    """
    Implements the ezpt protocol. A protocol that simply proxies data
    without obfuscating them.
    """
    def __init__(self):
        self.obf_proc = EzptProcess()
        self.unobf_proc = EzptProcess()
        reactor.spawnProcess(self.obf_proc, "/usr/games/rot13", ["rot13"], {})
        reactor.spawnProcess(self.unobf_proc, "/usr/games/rot13", ["rot13"], {})

    def receivedDownstream(self, data):
        """
        Got data from downstream; relay them upstream.
        """
        if not self.unobf_proc.stream:
            self.unobf_proc.set_stream(self.circuit.upstream)

        self.unobf_proc.transport.write(data.read())

    def receivedUpstream(self, data):
        """
        Got data from upstream; relay them downstream.
        """
        if not self.obf_proc.stream:
            self.obf_proc.set_stream(self.circuit.downstream)

        self.obf_proc.transport.write(data.read())
#        self.obf_proc.transport.closeStdin()

class EzptClient(EzptTransport):

    """
    EzptClient is a client for the 'ezpt' protocol.
    Since this protocol is so simple, the client and the server are identical and both just trivially subclass EzptTransport.
    """

    pass


class EzptServer(EzptTransport):

    """
    EzptServer is a server for the 'ezpt' protocol.
    Since this protocol is so simple, the client and the server are identical and both just trivially subclass EzptTransport.
    """

    pass



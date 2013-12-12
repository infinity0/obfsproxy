#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module contains an implementation of the 'ezpt' transport. """

from obfsproxy.transports.base import BaseTransport

from twisted.internet import reactor
from twisted.internet import protocol

import os

import obfsproxy.common.log as logging
log = logging.get_obfslogger()

class EzptProcess(protocol.ProcessProtocol):
    def __init__(self, stream):
        self.stream = stream

    def connectionMade(self):
        log.debug("Process started!")

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
        self.forward_args = ["rot13"]
        self.reverse_args = ["rot13"]

    def circuitConnected(self):
        """
        Circuit was completed, start the transform processes.
        """
        self.forward = EzptProcess(self.circuit.downstream)
        self.reverse = EzptProcess(self.circuit.upstream)
        # TODO(infinity0): tear down child procs when the circuit is closed
        reactor.spawnProcess(self.forward,
            self.forward_args[0], self.forward_args, os.environ)
        reactor.spawnProcess(self.reverse,
            self.reverse_args[0], self.reverse_args, os.environ)

        log.debug("%s: spawned new EZPT processes", self.name)

    def receivedDownstream(self, data):
        """
        Got data from downstream; relay them upstream.
        """
        self.reverse.transport.write(data.read())

    def receivedUpstream(self, data):
        """
        Got data from upstream; relay them downstream.
        """
        self.forward.transport.write(data.read())

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



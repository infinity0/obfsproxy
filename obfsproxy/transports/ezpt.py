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
        self.closing = False

    def outReceived(self, data):
        self.stream.write(data)

    def inConnectonLost(self):
        log.error("Child unexpectedly closed its stdin!")
        # TODO(infinity0): close the circuit with an error

    def outConnectionLost(self):
        if self.closing:
            return # expected
        log.error("Child unexpectedly closed its stdout!")
        # TODO(infinity0): close the circuit with an error

    def close(self):
        self.transport.loseConnection()
        self.closing = True
        # TODO(infinity0): detect that the child is actually closed after a
        # while (processEnded), and kill it if it hasn't. Twisted possibly
        # already handles this, check that it does.


class EzptTransport(BaseTransport):
    """
    Implements the ezpt protocol. A protocol that simply proxies data
    without obfuscating them.
    """
    def __init__(self):
        # stdbuf is only necessary for programs that use full-buffering on
        # non-terminal stdout. This includes most standard UNIX tools, but
        # hopefully not your PT which was specifically written with this
        # consideration in mind (i.e. it flushes output buffers immediately
        # whenever output is suitable for consumption). To test, run this:
        #
        # $ { echo lol; cat; } | your_program | cat
        #
        # If you see the transformation of "lol" appear immediately on the
        # terminal, then your_program does not need this workaround. If it does
        # not appear immediately, then it does need it.
        #
        # Note that this workaround does not work on Windows, so there you must
        # use a properly written program!
        self.workaround_stdbuf = True
        forward_args = ["rot13"]
        reverse_args = ["rot13"]

        if self.workaround_stdbuf:
            forward_args = ["stdbuf", "-o0"] + forward_args
            reverse_args = ["stdbuf", "-o0"] + reverse_args
        self.forward_args = forward_args
        self.reverse_args = reverse_args

    def circuitConnected(self):
        """
        Circuit was completed, start the transform processes.
        """
        self.forward = EzptProcess(self.circuit.downstream)
        self.reverse = EzptProcess(self.circuit.upstream)
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

    def circuitDestroyed(self, reason, side):
        log.debug("Circuit destroyed on %s: %s" % (side, reason))
        self.forward.close()
        self.reverse.close()


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



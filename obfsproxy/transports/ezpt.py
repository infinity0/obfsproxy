#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module contains an implementation of the 'ezpt' transport. """

from obfsproxy.transports.base import BaseTransport, PluggableTransportError

from twisted.internet import error
from twisted.internet import reactor
from twisted.internet import protocol

import os

import obfsproxy.common.log as logging
log = logging.get_obfslogger()


class EzptProcessSpec(object):

    def __init__(self, forward_args, reverse_args, stdbuf_workaround=False):
        """Create a new ProcessSpec.

        Args:
            forward_args: list of string, command line to run the program
                for the forward transformation (plain to obfuscated)
            reverse_args: list of string, command line to run the program
                for the reverse transformation (obfuscated to plain)
            stdbuf_workaround:
                This is necessary (but not sufficient) for programs that use
                libc automatic full-buffering on non-terminal stdout. This
                includes standard UNIX tools, but hopefully not your PT which
                was specifically written with this consideration in mind (i.e.
                flushes output buffers immediately whenever output is ready for
                consumption). To test, run this:

                $ { echo lol; cat; } | your_program | cat

                If you see the transformation of "lol" appear immediately on the
                terminal, then your_program does not need this workaround. If it
                does not appear immediately, then the workaround is necessary,
                but it may not be sufficient - specifically, programs that do
                their own buffering outside of libc, such as GNU base64. To
                check that the workaround does indeed work, run the above test
                again with `stdbuf -o0 your_program`.

                For simplicity, the workaround is either applied or not applied
                to both forward and reverse programs, so you need to run the
                test above (with and without the workaround) for both sides.

                Finally, this workaround does not work on Windows, so there you
                *must* use a properly written program!
        """
        self._forward_args = forward_args
        self._reverse_args = reverse_args
        self.stdbuf_workaround = stdbuf_workaround

    @property
    def forward_args(self):
        if self.stdbuf_workaround:
            return ["stdbuf", "-o0"] + self._forward_args
        return self._forward_args

    @property
    def reverse_args(self):
        if self.stdbuf_workaround:
            return ["stdbuf", "-o0"] + self._reverse_args
        return self._reverse_args


TEST_SPECS = {
    "id": EzptProcessSpec(
        ["cat"],
        ["cat"],
        stdbuf_workaround = False),
    "rot13": EzptProcessSpec(
        ["tr", "[a-zA-Z]", "[n-za-mN-ZA-M]"],
        ["tr", "[a-zA-Z]", "[n-za-mN-ZA-M]"],
        stdbuf_workaround = True),
    "xxd": EzptProcessSpec(
        ["xxd", "-p"],
        ["xxd", "-p", "-r"],
        stdbuf_workaround = True),
}


class EzptProcess(protocol.ProcessProtocol):

    def __init__(self, stream):
        self.stream = stream
        self.closing = False
        # lazily store errors until we actually need to detect them
        self.error = None

    def outReceived(self, data):
        self.stream.write(data)

    def inConnectonLost(self):
        msg = "Child unexpectedly closed its stdin!"
        self.error = error.ConnectionFdescWentAway(msg)
        log.error(msg)

    def outConnectionLost(self):
        if self.closing:
            return # expected
        msg = "Child unexpectedly closed its stdout!"
        self.error = error.ConnectionFdescWentAway(msg)
        log.error(msg)

    def close(self):
        if self.closing:
            return # ignore redundant double-close
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
        self.spec = TEST_SPECS["xxd"]

    def circuitConnected(self):
        """
        Circuit was completed, start the transform processes.
        """
        self.forward = EzptProcess(self.circuit.downstream)
        self.reverse = EzptProcess(self.circuit.upstream)
        reactor.spawnProcess(self.forward,
            self.spec.forward_args[0], self.spec.forward_args, os.environ)
        reactor.spawnProcess(self.reverse,
            self.spec.reverse_args[0], self.spec.reverse_args, os.environ)

        log.debug("%s: spawned new EZPT processes", self.name)

    def receivedDownstream(self, data):
        """
        Got data from downstream; relay them upstream.
        """
        if self.reverse.error:
            raise PluggableTransportError(
                "ezpt: Error on reverse process", self.reverse.error)
        self.reverse.transport.write(data.read())

    def receivedUpstream(self, data):
        """
        Got data from upstream; relay them downstream.
        """
        if self.forward.error:
            raise PluggableTransportError(
                "ezpt: Error on forward process", self.forward.error)
        self.forward.transport.write(data.read())

    def circuitDestroyed(self, reason, side):
        """
        Circuit was destroyed, close the transform processes.
        """
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



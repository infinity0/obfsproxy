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

    def __init__(self, name, stream):
        self.name = name
        # remote stream to redirect stdout to
        self.stream = stream
        # whether we are closing
        self.closing = False
        # lazily store errors until we actually need to detect them
        self.error = None
        # exit status, either ProcessDone or ProcessTerminate
        self.status = None

    def outReceived(self, data):
        self.stream.write(data)

    def errReceived(self, data):
        log.info("%s emitted stderr: %s", self.name, data.rstrip("\n"))

    def inConnectonLost(self):
        msg = "%s unexpectedly closed its stdin!" % self.name
        self.error = error.ConnectionFdescWentAway(msg)
        log.error(msg)

    def outConnectionLost(self):
        if self.closing:
            return # expected
        msg = "%s unexpectedly closed its stdout!" % self.name
        self.error = error.ConnectionFdescWentAway(msg)
        log.error(msg)

    def close(self):
        if self.closing:
            return # ignore redundant double-close
        self.transport.closeStdin()
        self.closing = True

    def processEnded(self, status):
        self.status = status.value

    def checkExit(self, kill=False):
        if self.status is None:
            if kill:
                log.info("kill %s since it has evaded death for too long!", self.name)
                self.transport.signalProcess('KILL')
            return False
        if isinstance(self.status, error.ProcessDone):
            log.debug("%s ended successfully", self.name)
        else:
            log.info("%s ended abnormally: %s", self.name, self.status)
        return True


class EzptTransport(BaseTransport):
    """
    Implements the ezpt protocol. A protocol that simply proxies data
    without obfuscating them.
    """
    def __init__(self):
        self.spec = TEST_SPECS["xxd"]

        super(EzptTransport, self).__init__()

    def circuitConnected(self):
        """
        Circuit was completed, start the transform processes.
        """
        self.forward = EzptProcess("proc_fwd_%s" % self.name, self.circuit.downstream)
        self.reverse = EzptProcess("proc_rev_%s" % self.name, self.circuit.upstream)
        reactor.spawnProcess(self.forward,
            self.spec.forward_args[0], self.spec.forward_args, os.environ)
        reactor.spawnProcess(self.reverse,
            self.spec.reverse_args[0], self.spec.reverse_args, os.environ)

        log.debug("%s: spawned new EZPT processes: fwd %s rev %s",
            self.name, self.spec.forward_args, self.spec.reverse_args)

    def receivedDownstream(self, data):
        """
        Got data from downstream; relay it to the reverse process.
        """
        if self.reverse.error:
            raise PluggableTransportError(
                "ezpt: Error on reverse process", self.reverse.error)
        self.reverse.transport.write(data.read())

    def receivedUpstream(self, data):
        """
        Got data from upstream; relay it to the forward process.
        """
        if self.forward.error:
            raise PluggableTransportError(
                "ezpt: Error on forward process", self.forward.error)
        self.forward.transport.write(data.read())

    def circuitDestroyed(self, reason, side):
        """
        Circuit was destroyed, close the transform processes.
        """
        log.debug("Circuit %s destroyed on %s: %s" % (self.circuit.name, side, reason))
        self.forward.close()
        self.reverse.close()
        def cleanUp(timeout, multiplier, max_to, kill_to):
            maybeKill = timeout > kill_to
            if (self.forward.checkExit(maybeKill) and
                self.reverse.checkExit(maybeKill)):
                log.debug("%s: cleaned up EZPT processes", self.name)
                del self.forward
                del self.reverse
                return
            next_to = timeout * multiplier
            reactor.callLater(next_to,
                cleanUp, min(next_to, max_to), multiplier, max_to, kill_to)
        reactor.callLater(0.25, cleanUp, 0.25, 1.5, 120, 30)


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



#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This module contains an implementation of the 'ezpt' transport.

EZPT is an easy way of testing out new pluggable transport ideas that only
involve transforming a single input stream into a single output stream.

Often, you can implement this quickly using a program that reads from its
stdin, transforms this stream, and writes to its stdout. (This program could
even be a shell script that pipes many programs together!)

This PT serves as the wrapper around a simple stdin-stdout program to turn
it into a fully-functional pluggable transport. Note that you actually need
two programs - one for going forward, processing data to be sent, and
one for going back, processing data that was received.

This PT is disabled until you set the env vars EZPT_ENCODE and EZPT_DECODE.
These are command-line strings, and will be parsed by the python shlex
module into a command-line list, to be run for the encoding and decoding
options respectively. (The shell is not invoked and no variables are
expanded within the string; we only use its syntax for convenience.)

If you need to do this in torrc, and you are not using Windows, you may use
env(1) to set these variables.

A few examples follow. ALL OF THESE ARE INSECURE AND SHOULD NOT BE USED IN
PRODUCTION. Read further below for what extra options mean:

# output each byte twice:
EZPT_ENCODE="perl -e '$|=1;while(read(STDIN,$_,1)){print \"$_$_\";}'" \
EZPT_DECODE="perl -e '$|=1;while(read(STDIN,$_,2)){print chop;}'" \
obfsproxy ezpt

# xor255 every byte:
EZPT_ENCODE="perl -e '$|=1;while(read(STDIN,$_,1)){print chr(ord^0xff);}'" \
EZPT_DECODE="perl -e '$|=1;while(read(STDIN,$_,1)){print chr(ord^0xff);}'" \
obfsproxy ezpt

# hex-encode every byte:
EZPT_STDBUF_WORKAROUND=1 \
EZPT_ENCODE='xxd -p' \
EZPT_DECODE='xxd -p -r' \
obfsproxy ezpt

# rot13 every byte:
EZPT_STDBUF_WORKAROUND=1 \
EZPT_ENCODE='tr "[a-zA-Z]" "[n-za-mN-ZA-M]"' \
EZPT_DECODE='tr "[a-zA-Z]" "[n-za-mN-ZA-M]"' \
obfsproxy ezpt

Some other env vars you may set:

EZPT_STDBUF_WORKAROUND=0|1
This is needed for some core unix tools to function correctly with EZPT. If
you are writing your own encoder/decoder, you are strongly discouraged from
relying on this. See the doc for EzptProcessSpec for details on when this is
appropriate.

"""

from obfsproxy.transports.base import BaseTransport, PluggableTransportError

from twisted.internet import error
from twisted.internet import reactor
from twisted.internet import protocol

import shlex
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

    def __repr__(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__,
            self._forward_args, self._reverse_args, self.stdbuf_workaround)

    @classmethod
    def parseFromEnv(cls):
        forward_str = os.getenv("EZPT_ENCODE")
        reverse_str = os.getenv("EZPT_DECODE")
        if not forward_str or not reverse_str:
            raise ValueError("ezpt: no command set")
        stdbuf_workaround = bool(int(os.getenv("EZPT_STDBUF_WORKAROUND", "0")))
        return cls(shlex.split(forward_str), shlex.split(reverse_str), stdbuf_workaround)


EZPT_SPEC_FROM_ENV = None


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
        """
        Returns whether the process has exited. If kill is True, then
        try to kill (SIGKILL) the process if it is currently alive.
        """
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
        assert EZPT_SPEC_FROM_ENV is not None
        self.spec = EZPT_SPEC_FROM_ENV

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

        We schedule periodic checks that the child processes are actually dead,
        killing them after about a minute if they refuse to die.
        """
        log.debug("Circuit %s destroyed on %s: %s", self.circuit.name, side, reason)
        self.forward.close()
        self.reverse.close()
        def cleanUp(timeout, multiplier, max_to, kill_to):
            # timeout: time before next check
            # multiplier: multiplier for next timeout
            # max_to: max timeout
            # kill_to: max timeout before a kill is issued
            maybeKill = timeout > kill_to
            if (self.forward.checkExit(maybeKill) and
                self.reverse.checkExit(maybeKill)):
                log.debug("%s: cleaned up EZPT processes", self.name)
                del self.forward, self.reverse
                return
            next_to = timeout * multiplier
            reactor.callLater(next_to,
                cleanUp, min(next_to, max_to), multiplier, max_to, kill_to)
        # ["%.2g" % (0.25*(1.8**x)) for x in xrange(12)]
        # ['0.25', '0.45', '0.81', '1.5', '2.6', '4.7', '8.5', '15', '28', '50', '89', '1.6e+02']
        reactor.callLater(0.25, cleanUp, 0.25, 1.8, 120, 30)


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



def get_all_transports():
    """
    Returns all transports that EZPT has been configured to support. This is a
    list-of-pairs of (transport_name:str, transport_classes:dict).

    For examples of transport_classes and how these are used, see
    obfsproxy.transports.transports.
    """
    global EZPT_SPEC_FROM_ENV
    try:
        EZPT_SPEC_FROM_ENV = EzptProcessSpec.parseFromEnv()
        log.info("ezpt configured from environment: %r", EZPT_SPEC_FROM_ENV)
        return [('ezpt', {'base': EzptTransport, 'client' : EzptClient, 'server' : EzptServer })]
    except ValueError, e:
        return []


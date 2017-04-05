
import os
import logging
import subprocess
import shlex
import socket
import time

logger = logging.getLogger(__name__)

class HostChecker:
    """
    The HostChecker class starts, stops, and interfaces to the java host checker which
    is required for some juniper vpn connections.  The host checker is started with parameters
    pulled from the sign in webpage and sent the preauth key.  The host checker connects
    to the vpn and returns a response key that is used to complete the sign in.
    """

    defaultParams = {
        'loglevel' : '2',
        'postRetries' : '6',
        'ivehost' : '',
        'Parameter0' : '',
        'locale' : 'en',
        'home_dir' : os.path.expanduser('~'),
        'user_agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:48.0) Gecko/20100101 Firefox/48.0'
    }

    def __init__(self, jar, narport):
        self.jar = jar
        self.narporttxt = narport
        self.hcpid = None
        self.port = 0

    def exists(self):
        return os.path.exists(self.jar)

    def isRunning(self):
        try:
            if not self.hcpid is None:
                self.hcpid.poll()
                if self.hcpid.returncode is None:
                    return True
        except:
            pass
        return False

    def startHostChecker(self, params):
        self.stopHostChecker()

        # check params passed to host checker and use defaults for any not set
        paramStr = ''
        for param in HostChecker.defaultParams.keys():
            if not param in params.keys():
                paramStr = paramStr + param + ' "' + HostChecker.defaultParams[param] + '" '
            else:
                paramStr = paramStr + param + ' "' + params[param] + '" '

        # remove old narport.txt file
        if os.path.exists(self.narporttxt):
            os.remove(self.narporttxt)

        # build the comand to start the host checker
        cmd = 'java -classpath %s net.juniper.tnc.NARPlatform.linux.LinuxHttpNAR %s' % (self.jar, paramStr)
        logger.debug('Staring host checker with cmd %s', cmd)
        cmd = shlex.split(cmd)
        self.hcpid = subprocess.Popen(cmd, stdin=subprocess.PIPE)

        # wait up to 20 seconds for narport.txt
        # on initial start, it can take a while for java to launch the host checker
        for i in range(1, 20):
            if os.path.exists(self.narporttxt):
                break
            time.sleep(1)

        # open narport and get port number for socket
        with open(self.narporttxt, 'r') as nptxt:
            self.port = int(nptxt.read())
            logger.debug('Got host checker port as %i', self.port)

    def stopHostChecker(self):
        # first kill the process we have started
        if self.isRunning():
            self.hcpid.terminate()
            time.sleep(1)
            if self.isRunning():
                logger.error("Failed to stop host checker")
        self.hcpid = None

    def send(self, data, timeout=5):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(('127.0.0.1', self.port))
        logger.debug('Sending data to host checker %s', data)
        sock.sendall(data)
        resp = sock.recv(2048)
        sock.close()
        logger.debug('Got response from host checker %s', resp)
        return resp

    def doCheck(self, preauth, host):
        """
        Sends the running host checker the vpn site and the preauth cookie.
        Expects the host checker to return a multiline response that starts with '200'
        meaning the host check was successful. Returns the host check response
        on success, raises an exception on failure.
        """
        data = 'start\nIC=%s\nCookie=%s\nDSSIGNIN=null\n' % (host, preauth)
        resp = ""
        try:
            resp = self.send(data)
        except socket.timeout:
            # ignore socket timeout which is expected since recv buffer will not fill up entirely
            logger.warning('Got socket timeout exception, ignoring...')
        resp = resp.splitlines()
        if len(resp) < 1:
            raise Exception('No response from host checker')
        if not '200' in resp[0]:
            raise Exception('Invalid response from host checker %s' % resp[0])
        return resp

    def sendCookie(self, value):
        try:
            self.send('setcookie\nCookie=%s\n' % value, 2)
        except socket.timeout:
            # expect send function to timeout waiting for receive since host checker doesn't respond to this command
            pass

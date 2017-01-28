
import os, signal, time
from datetime import timedelta, datetime
import urllib, urllib2, cookielib, ssl, socket, urlparse
import subprocess, shlex
import threading
import re
import copy
from enum import Enum
import logging

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
        logging.debug('Staring host checker with cmd %s' % cmd)
        cmd = shlex.split(cmd)
        self.hcpid = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        
        # wait up to 10 seconds for narport.txt
        for i in range(1, 10):
            if os.path.exists(self.narporttxt): break
            time.sleep(1)

        # open narport and get port number for socket 
        with open(self.narporttxt, 'r') as np:
            self.port = int(np.read())
            logging.debug('Got host checker port as %i' % self.port)

    def stopHostChecker(self):
        # first kill the process we have started
        if not self.hcpid is None:
            self.hcpid.poll()
            if self.hcpid.returncode is None:
                self.hcpid.terminate()
                time.sleep(1)
                self.hcpid.poll()
                if self.hcpid.returncode is None:
                    self.hcpid.kill()
            else:
                print self.hcpid.returncode
        self.hcpid = None

    def send(self, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', self.port))
        logging.debug('Sending data to host checker %s' % data)
        sock.sendall(data)
        resp = sock.recv(2048)
        sock.close()
        logging.debug('Got response from host checker %s' % resp)
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
            print 'Got socket timeout exception, ignoring...'
            pass
        resp = resp.splitlines()
        if len(resp) < 1:
            raise Exception('No response from host checker')
        if not '200' in resp[0]:
            raise Exception('Invalid response from host checker %s' % resp[0])
        return resp

    def sendCookie(self, value):
        try:
            self.send('setcookie\nCookie=%s\n' % value)
        except socket.timeout:
            # expect send function to timeout waiting for receive since host checker doesn't respond to this command
            pass

class ConnectionInfo:
    host = ""
    status = "Disconnected"
    ip = ""
    bytesSent = 0
    bytesRecv = 0
    duration = timedelta()
    startDateTime = datetime.fromtimestamp(0)
    keepAliveStatus = ""

class SignInStatus:

    def __init__(self):
        self.signedIn = False
        self.status = 'Uknown'
        self.first = ''
        self.last = ''
        self.dt0 = datetime.fromtimestamp(0)

    def updateStatus(self, dsid, first, last):
        if dsid is None:
            self.signedIn = False
            self.status = 'Not Signed In'
            self.first = ''
            self.last = ''
            self.firstdt = self.dt0
            self.lastdt = self.dt0
            return
        self.firstdt = self.parseDt(first)
        self.lastdt = self.parseDt(last)

        if self.firstdt > self.dt0:
            if self.isElasped(self.firstdt, timedelta(hours=24)):
                self.status = 'Signed Out, Session Expired'
                self.signedIn = False
            else:
                self.status = 'Signed in'
                self.signedIn = True
            self.first = self.firstdt.isoformat()
        else:
            self.first = ''
        
        if self.lastdt > self.dt0:
            if self.isElasped(self.lastdt, timedelta(hours=1)):
                self.status = 'Signed Out Due to Inactivity'
                self.signedIn = False
            else:
                self.status = 'Signed in'
                self.signedIn = True
            self.last = self.firstdt.isoformat()
        else:
            self.last = ''

    def isElasped(self, dt, td):
        elapsed = datetime.now() - dt
        return elapsed > td

    def parseDt(self, dtstr):
        try:
            dt = datetime.fromtimestamp(int(dtstr))
            return dt
        except:
            return datetime.fromtimestamp(0)

    def __str__(self):
        string = '%s\n%s\n%s\n' %( self. status, self.first, self.last )
        return string

    def getDict(self):
        return {'status': self.status, 'first': self.first, 'last': self.last}


class JuniperClientInterface:
    """ Class that should be inherited from and overridden to get status callbacks """
    def __init__(self):
        pass

    def onSignInStatusUpdated(self):
        pass

    def onConnectionInfoUpdated(self):
        pass

    def onSslCertChanged(self, newcert, oldcert=None):
        pass

class JuniperClient:
    """
    Class to sign in/out, run host checker, and connect to a Juniper VPN.
    The juniper ncui library is executed using a ncui wrapper which 
    loads the ncui libray and calls the main function in the library.

    User must have already logged into the VPN using a browser in order
    to download and install the juniper client binaries needed by this script.
    """

    def __init__(self):
        self.jndir = os.path.expanduser("~/.juniper_networks/")
        self.ncdir = os.path.join(self.jndir, 'network_connect/')
        self.cert = os.path.join(self.jndir, "network_connect/ssl.crt")

        # the ncui wrapper has to be run from the network_connect directory
        self.ncui = os.path.join(self.ncdir, 'ncui_wrapper')

        # create cookie jar and store cookies in juniper directory
        self.cj = cookielib.LWPCookieJar(filename=os.path.join(self.jndir, 'jccl.txt'))
        if os.path.exists(self.cj.filename):
            self.cj.load()
        
        self.hostChecker = HostChecker(os.path.join(self.jndir, 'tncc.jar'), os.path.join(self.jndir, 'narport.txt'))
        self.host = ""
        self.DSID = ""

        # create ssl opener with our cookie jar to be used for all the web based interactions
        self.opener = urllib2.build_opener(urllib2.HTTPSHandler(context = ssl._create_unverified_context()), urllib2.HTTPCookieProcessor(self.cj))
        self.opener.addheaders = [('User-agent', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:48.0) Gecko/20100101 Firefox/48.0')]

        self.connectThread = None
        self.ncuiProc = None
        self.doConnect = False
        self.doDisconnect = False
        self.isConnected = False

        # create sign in status and update based on currently loaded cookies
        self.signInStatus = SignInStatus()
        self.signInStatus.updateStatus(self.getCookie('DSID'), self.getCookie('DSFirstAccess'), self.getCookie('DSLastAccess'))

        self.connectInfo = ConnectionInfo()

        self.statusUpdatedCb = self.onStatusUpdatedCb

    def checkForNcui(self):
        return os.path.exists(self.ncui)

    def setConfig(self, host, port, urlnum, realm):
        self.host = host
        self.port = port
        self.baseurl = 'https://%s:%i/dana-na/auth' % (host, port)
        self.loginurl = '%s/%s/login.cgi' % (self.baseurl, urlnum)
        self.welcomeurl = '%s/%s/welcome.cgi' % (self.baseurl, urlnum)
        self.logouturl = '%s/logout.cgi' % self.baseurl
        self.homeurl = 'https://%s:%i/dana/home/index.cgi' % (host, port)
        self.realm = realm

    def getSslCert(self):
        pemcert = ssl.get_server_certificate((self.host, self.port), ssl_version=ssl.PROTOCOL_SSLv23)
        dercert = ssl.PEM_cert_to_DER_cert(pemcert)
        return dercert, pemcert

    def saveSslCert(self, cert):
        with open(self.cert, mode="w") as certfile:
            certfile.write(cert)

    def getCookie(self, cookie):
        for c in self.cj:
            if c.name == cookie:
                return c.value
        return None

    def printCookies(self):
        for cookie in self.cj:
            print '%s = %s' % (cookie.name, cookie.value)

    def parseParams(self, text):
        params = {}
        for line in text.splitlines():
            if not 'PARAM' in line:
                continue
            parts = line.split('"')
            params[parts[1]] = parts[3]
        return params

    def checkSignIn(self):
        """
        Accesses the vpn home index.cgi with current cookies.  If we are signed in, the DSLastAccess
        will be updated and the isSignedIn check will pass. If we are not signed in, the vpn 
        will redirect us back to welcome.cgi and clear all the cookies including DSID.
        """
        logging.debug('Accessing home url %s' % self.homeurl)
        request = self.opener.open(self.homeurl)
        resp = request.read()
        self.cj.save()
        self.signInStatus.updateStatus(self.getCookie('DSID'), self.getCookie('DSFirstAccess'), self.getCookie('DSLastAccess'))
        return self.signInStatus.signedIn

    def signIn(self, username, pin, token):
        # How sign in works
        # 1. open https connection to login url with login parameters set
        # 2. check response for login failure, already logged in, and host checker
        # 3. if host check, use the DSPREAUTH cookie value to do the host check
        # 4. once logged in/host is checked, start ncui using the DSID

        # not sure if the sel_auth cookie is needed, but set it here since browser does
        cookie = cookielib.Cookie(version=0, name='sel_auth', value='otp', port=None, port_specified=False, 
            domain=self.host, domain_specified=False, domain_initial_dot=False, path='/', 
            path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        self.cj.set_cookie(cookie)

        # set cookie for DSCheckBrowser to java so vpn site will give us host check parameters for java host checker
        cookie = cookielib.Cookie(version=0, name='DSCheckBrowser', value='java', port=None, port_specified=False, 
            domain=self.host, domain_specified=False, domain_initial_dot=False, path='/', 
            path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        self.cj.set_cookie(cookie)

        # create the login parameters
        loginParams = urllib.urlencode({'username'  : username,
                                      'password'  : pin + token,
                                      'realm'     : self.realm,
                                      'pin'       : pin,
                                      'token'     : token})
        logging.debug('Logging in with parameters %s' % loginParams)
        self.updateSignInStatus('Signing In with username %s' % username)
        request = self.opener.open(self.loginurl, loginParams)
        resp = request.read()
        self.cj.save()

        if "Invalid username or password" in resp:
            self.updateSignInStatus('Sign in failed, invalid username or password')
            raise Exception("Invalid username or password, re-enter your information and try again")

        if 'Host Checker' in resp:
            self.updateSignInStatus('Running host checker')
            resp = self.checkHost(request, resp)

        self.DSID = self.getCookie('DSID')
        if self.DSID is None:
            self.updateSignInStatus('Sign in failed, DSID not found after host check')
            logging.error('Login failed, DSID not found in sign in response')
            raise Exception('Failed to get DSID when signing in')
        self.updateSignInStatus('Sign in successful')
        logging.debug('Logged in and got DSID as %s' % self.DSID)

        # check for other login sessions after host check
        if 'id="DSIDConfirmForm"' in resp:
            print resp
            logging.info('Found other active session, leaving it open and continuing')
            #formData = m/name="FormDataStr" value="([^"]+)"/
            contParams = urllib.urlencode({'btnContinue':'Continue the session', 'FormDataStr': formData})
            request = self.opener.open(self.loginurl, contParams)
            resp = request.read()
            print resp
            self.cj.save()

    def checkHost(self, request, resp):
        # How the host checker works
        # 1. After login, the returned page gives you parameters for the host checker and a state id (via url redirection in the location header of the response) and also a preauth key
        # 2. The host checker is started with the parameters embedded in the login page
        # 3. The preauth key and host are sent to the host checker over a socket
        # 4. The host checker responds with a key to the preauth key 
        # 5. The responded key is passed back to the vpn site along with some other parameters
        # 6. The vpn site responds back with a DSID needed to connect to the VPN

        # make sure the host checker jar is already downloaded
        if not os.path.exists(os.path.join(self.jndir, 'tncc.jar')):
            self.updateSignInStatus('Host check failed, missing tncc.jar')
            logging.error('Cannot run host checker, tncc.jar does not exist at %s' % os.path.join(self.jndir, 'tncc.jar'))
            raise Exception("VPN requires host checker but tncc.jar does not exist. Please login from a browser to download components.")

        # make sure we got the preauth key
        preauth = self.getCookie('DSPREAUTH')
        if preauth is None:
            self.updateSignInStatus('Host check failed, missing  DSPREAUTH')
            logging.error('Preauth key not found in login response.')
            raise Exception('Host check failed, failed to get DSPREAUTH cookie')

        # get the state id and realm id from the new url returned from the login
        parsedParams = urlparse.parse_qs(request.geturl())
        stateid = parsedParams['id'][0].split('_')[1]
        signinRealmId = parsedParams['signinRealmId'][0]

        # get params from resp to start host checker, params are in the form
        # <PARAM NAME="name" VALUE="5.0">
        params = self.parseParams(resp)
        self.hostChecker.startHostChecker(params)
        # do the host check and get the response which contains the response key
        hcresp = self.hostChecker.doCheck(preauth, self.host)
        
        # set the response key as the new DSPREAUTH cookie value
        cookie = cookielib.Cookie(version=0, name='DSPREAUTH', value=hcresp[2], port=None, port_specified=False, 
            domain=self.host, domain_specified=False, domain_initial_dot=False, path='/dana-na/', 
            path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        self.cj.set_cookie(cookie)
        # set params needed to send the host check response key
        params = urllib.urlencode({'loginmode'  : 'mode_postAuth', 'postauth'  : 'state_%s' % stateid})
        self.updateSignInStatus('Sending host check response key')
        logging.debug('Sending preauth %s' % params)                                
        request = self.opener.open(self.loginurl, params)
        resp = request.read()
        self.cj.save()

        preauth = self.getCookie('DSPREAUTH')
        if preauth is None:
            self.updateSignInStatus('Host check failed, no response to post auth key')
            logging.error('Host check failed, no preauth cookie in response to host check post auth')
            raise Exception('Host check failed, failed to get DSPREAUTH cookie')
        
        # send preauth cookie to host checker, not sure why this is needed
        self.hostChecker.sendCookie(preauth)
        return resp
    
    def signOut(self):
        self.updateSignInStatus('Signing out')
        request = self.opener.open(self.logouturl)
        resp = request.read()
        if not 'Your session has been terminated' in resp:
            self.updateSignInStatus('Sign out failed')
            # signout failed, maybe user no longer has network connection
            return False
        self.updateSignInStatus('Sign out succeeded')
        return True

    def getDevInfo(self, dev):
        info = []
        with open("/proc/net/dev", mode="r") as f:
            for l in f:
                match = re.match(r"^\s*(%s[0-9])" % dev, l)
                if match is None:
                    continue
                info = l.split()
                break
        try:
            ip = os.popen('ip addr show %s' % info[0].split(":")[0]).read().split("inet ")[1].split("/")[0]
            # ip, recv, sent
            devInfo = (ip, int(info[1]), int(info[9]))
            return devInfo
        except:
            return ()

    def getConnectionInfo(self):
        ci = copy.copy(self.connectInfo)
        return ci

    def getSignInStatus(self):
        return self.signInStatus.getDict()

    def startConnectThread(self):
        if self.connectThread is None:
            self.connectThread = threading.Thread(target = self.connectThreadRun)
            self.connectThread.start()

    def stopConnectThread(self):
        self.stop = True
        if not self.connectThread is None:
            self.connectThread.join(2)

    def disconnect(self):
        self.doDisconnect = True
        self.stopNCui()
        self.hostChecker.stopHostChecker()

    def connect(self):
        DSID = self.getCookie('DSID')
        if DSID is None or len(DSID) == 0:
            raise Exception("Can't connect, DSID value is invalid.")
        self.doConnect = True

    def onStatusUpdatedCb(self, connectInfo, signInStatus):
        #print 'got default status updated'
        pass

    def updateConnectInfo(self, status = "", ip = "", sent = 0, recv = 0):
        self.connectInfo.status = status
        self.connectInfo.ip = ip
        self.connectInfo.bytesRecv = sent
        self.connectInfo.bytesSent = recv
        self.statusUpdatedCb( self.connectInfo, self.signInStatus.getDict())

    def updateSignInStatus(self, status = ""):
        self.signInStatus.status = status
        self.statusUpdatedCb( self.connectInfo, self.signInStatus.getDict())

    def checkNetwork(self):
        try:
            cmd = "/bin/bash -c \"ip route | grep default | grep -v tun | awk '{print $3}'\""
            cmd = shlex.split(cmd)
            gateway = subprocess.check_output(cmd)
            cmd = "ping -c 1 -W 2 %s >/dev/null 2>&1" % gateway
            cmd = shlex.split(cmd)
            subprocess.check_output(cmd)
            return True
        except subprocess.CalledProcessError as cpe:
            return False

    def fixRoutes(self):
        try:
            cmd = "/bin/bash -c \"ip route | grep 'metric 10' | grep -v default\""
            cmd = shlex.split(cmd)
            output = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as cpe:
            output = cpe.output

        for line in output.split('\n'):
            return
            newRoute = line.replace("metric 10", "metric 0")
            cmd = "ip route replace %s" % newRoute
            cmd = chlex.split(cmd)
            retcode = subprocess.call(cmd)
            if retcode != 0:
                print "Error fixing hijacked route: %d = %s " % (retcode, cmd)

    def connectThreadRun(self):

        State = Enum('State', 'Wait Connected Connecting ConnectWait Disconnect')
        devName = "tun"
        self.stop = False
        state = State.Wait
        waitConnect = 0
        self.updateConnectInfo("Disconnected")
        while self.stop is False:
            devInfo = self.getDevInfo(devName)
            if len(devInfo) >= 3:
                self.isConnected = True
            else:
                self.isConnected = False

            #networkStatus =

            # state wait to connect/check if connected
            if state == State.Wait:
                if self.doConnect:
                    self.doConnect = False
                    state = State.Connecting
                elif self.doDisconnect:
                    self.doDisconnect = False
                    state = State.Disconnect
                elif self.isConnected:
                    state = State.Connected

            # state connected
            elif state == State.Connected:
                if not self.isConnected:
                    self.updateConnectInfo("Connection Lost")
                    state = State.Wait
                elif self.doDisconnect:
                    state = State.Disconnect
                else:
                    self.connectInfo.duration = datetime.now() - self.connectInfo.startDateTime
                    self.updateConnectInfo("Connected", devInfo[0], devInfo[1], devInfo[2])
                    # check vpn connection

            # state disconnect
            elif state == State.Disconnect:
                self.stopNCui()
                self.updateConnectInfo("Disconnected")
                state = State.Wait

            # state start connect
            elif state == State.Connecting:
                self.updateConnectInfo("Connecting")
                self.startNcui()
                waitConnect = 0
                state = State.ConnectWait

            # state wait connect
            elif state == State.ConnectWait:
                waitConnect = waitConnect + 1
                if self.isConnected:
                    self.connectInfo.startDateTime = datetime.now()
                    self.fixRoutes()
                    state = State.Connected
                elif waitConnect >= 5:
                    self.updateConnectInfo("Failed to Connect")
                    self.stopNCui()
                    state = State.Wait

            time.sleep(1)
        self.stopNCui()

    def startNcui(self):
        self.stopNCui()
        cmd = '%s -h %s -c DSID=%s -f %s' % (self.ncui, self.host, self.DSID, self.cert)
        logging.debug('Starting ncui with command: %s' % cmd)
        cmd = shlex.split(cmd)
        self.ncuiProc = subprocess.Popen(cmd, stdin=subprocess.PIPE, cwd=self.ncdir)
        # send <enter> to Password prompt that pops up after
        # starting the NCUI binary
        self.ncuiProc.stdin.write("\n")

    def stopNCui(self):
        # first kill the process we have started
        if not self.ncuiProc is None:
            self.ncuiProc.poll()
            if self.ncuiProc.returncode is None:
                self.ncuiProc.terminate()
                time.sleep(1)
                self.ncuiProc.poll()
                if self.ncuiProc.returncode is None:
                    self.ncuiProc.kill()
            else:
                print self.ncuiProc.returncode

        # second kill any processes we didn't start
        try:
            pids = map(int, subprocess.check_output(["pidof", "ncui_wrapper"]).split())
            for pid in pids:
                os.kill(pid, signal.SIGTERM)
            if len(pids) > 0: time.sleep(1)
            pids = map(int, subprocess.check_output(["pidof", "ncui_wrapper"]).split())
            for pid in pids:
                os.kill(pid, signal.SIGKILL)
            if len(pids) > 0: time.sleep(1)
        except:
            # if no pids are found, will throw an exception or if pid doesn't exist for kill
            pass

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    jc = JuniperClient()
    #jc.checkSignIn()
    #print jc.signInStatus
    jc.updateConnectInfo('idk')
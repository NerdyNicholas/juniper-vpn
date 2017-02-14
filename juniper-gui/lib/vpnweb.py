
import os
import urllib
import urlparse
import ssl
import logging
from datetime import datetime, timedelta

from hostchecker import HostChecker
from vpnopener import VpnOpener

class SignInStatus:

    def __init__(self):
        self.signedIn = False
        self.status = 'Unknown'
        self.first = ''
        self.last = ''
        self.dt0 = datetime.fromtimestamp(0)
        self.firstdt = self.dt0
        self.lastdt = self.dt0

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
        string = '%s\n%s\n%s\n' %(self. status, self.first, self.last)
        return string

    def getDict(self):
        return {'status': self.status, 'first': self.first, 'last': self.last}

class VpnWeb:
    """
    Performs web based transactions to the juniper web portal such as
    signing in/out and running host checker.
    """

    def __init__(self, jndir):
        self.jndir = jndir
        self.host = ''
        self.realm = ''
        self.port = 443
        self.baseurl = ''
        self.loginurl = ''
        self.welcomeurl = ''
        self.logouturl = ''
        self.homeurl = ''
        self.dsid = ''
        self.username = ""
        self.pin = ""
        self.token = ""

        # create vpn opener to handle https and cookie operations
        # cookie file will be stored in juniper directory
        self.opener = VpnOpener(os.path.join(self.jndir, 'jccl.txt'))

        self.hostChecker = HostChecker(os.path.join(self.jndir, 'tncc.jar'), os.path.join(self.jndir, 'narport.txt'))

        # create sign in status and update based on currently loaded cookies
        self.signInStatus = SignInStatus()
        self.signInStatus.updateStatus(self.opener.getCookie('DSID'), self.opener.getCookie('DSFirstAccess'), self.opener.getCookie('DSLastAccess'))

    def setConfig(self, host, port, urlnum, realm):
        self.host = host
        self.port = port
        self.baseurl = 'https://%s:%i/dana-na/auth' % (host, port)
        self.loginurl = '%s/%s/login.cgi' % (self.baseurl, urlnum)
        self.welcomeurl = '%s/%s/welcome.cgi' % (self.baseurl, urlnum)
        self.logouturl = '%s/logout.cgi' % self.baseurl
        self.homeurl = 'https://%s:%i/dana/home/index.cgi' % (host, port)
        self.realm = realm

    def setCredentials(self, username, pin, token):
        self.username = username
        self.pin = pin
        self.token = token

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
        logging.debug('Accessing home url %s', self.homeurl)
        self.opener.open(self.homeurl)
        self.signInStatus.updateStatus(self.opener.getCookie('DSID'), self.opener.getCookie('DSFirstAccess'), self.opener.getCookie('DSLastAccess'))
        return self.signInStatus.signedIn

    def checkSignInAndError(self):
        try:
            if self.checkSignIn():
                return 0
            else:
                return -1
        except Exception as e:
            return -2

    def getSignInStatus(self):
        self.signInStatus.updateStatus(self.opener.getCookie('DSID'), self.opener.getCookie('DSFirstAccess'), self.opener.getCookie('DSLastAccess'))
        return self.signInStatus.getDict()

    def updateSignInStatus(self, status):
        self.signInStatus.updateStatus(self.opener.getCookie('DSID'), self.opener.getCookie('DSFirstAccess'), self.opener.getCookie('DSLastAccess'))
        self.signInStatus.status = status

    def signInWithCredentials(self):
        self.signIn(self.username, self.pin, self.token)

    def signIn(self, username, pin, token):
        # How sign in works
        # 1. open https connection to login url with login parameters set
        # 2. check response for login failure, already logged in, and host checker
        # 3. if host check, use the DSPREAUTH cookie value to do the host check
        # 4. once logged in/host is checked, start ncui using the DSID

        self.opener.setupLoginCookies(self.host)
        # create the login parameters
        loginParams = urllib.urlencode({'username'  : username,
                                        'password'  : pin + token,
                                        'realm'     : self.realm,
                                        'pin'       : pin,
                                        'token'     : token})
        logging.debug('Logging in with parameters %s', loginParams)
        self.updateSignInStatus('Signing In with username %s' % username)
        resp = self.opener.open(self.loginurl, loginParams)

        if "Invalid username or password" in resp:
            self.updateSignInStatus('Sign in failed, invalid username or password')
            raise Exception("Invalid username or password, re-enter your information and try again")

        if 'Host Checker' in resp:
            self.updateSignInStatus('Running host checker')
            resp = self.checkHost(self.opener.request.geturl(), resp)

        self.dsid = self.opener.getCookie('DSID')
        if self.dsid is None:
            self.updateSignInStatus('Sign in failed, DSID not found after host check')
            logging.error('Login failed, DSID not found in sign in response')
            logging.debug("%s", resp)
            self.opener.printCookies()
            raise Exception('Failed to get DSID when signing in')
        self.updateSignInStatus('Sign in successful')
        logging.debug('Logged in and got DSID as %s', self.dsid)

        # check for other login sessions after host check
        if 'id="DSIDConfirmForm"' in resp:
            logging.info('Found other active session, leaving it open and continuing')
            #formData = m/name="FormDataStr" value="([^"]+)"/
            formData = ""
            contParams = urllib.urlencode({'btnContinue':'Continue the session', 'FormDataStr': formData})
            resp = self.opener.open(self.loginurl, contParams)
            logging.debug("%s", resp)
            self.opener.printCookies()

    def checkHost(self, url, resp):
        # How the host checker works
        # 1. After login, the returned page gives you parameters for the host checker and a state id
        # (via url redirection in the location header of the response) and also a preauth key
        # 2. The host checker is started with the parameters embedded in the login page
        # 3. The preauth key and host are sent to the host checker over a socket
        # 4. The host checker responds with a key to the preauth key
        # 5. The responded key is passed back to the vpn site along with some other parameters
        # 6. The vpn site responds back with a DSID needed to connect to the VPN

        # make sure the host checker jar is already downloaded
        if not self.hostChecker.exists():
            # TODO: download host checker, path is given in response
            self.updateSignInStatus('Host check failed, missing tncc.jar')
            logging.error('Cannot run host checker, tncc.jar does not exist at %s', self.hostChecker.jar)
            raise Exception("VPN requires host checker but tncc.jar does not exist. Please login from a browser to download components.")

        # make sure we got the preauth key
        preauth = self.opener.getCookie('DSPREAUTH')
        if preauth is None:
            self.updateSignInStatus('Host check failed, missing  DSPREAUTH')
            logging.error('Preauth key not found in login response.')
            logging.debug("%s %s", url, resp)
            self.opener.printCookies()
            raise Exception('Host check failed, failed to get DSPREAUTH cookie')

        # get the state id and realm id from the new url returned from the login
        parsedParams = urlparse.parse_qs(url)
        stateid = parsedParams['id'][0].split('_')[1]
        signinRealmId = parsedParams['signinRealmId'][0]

        # get params from resp to start host checker, params are in the form
        # <PARAM NAME="name" VALUE="5.0">
        params = self.parseParams(resp)
        self.hostChecker.startHostChecker(params)
        # do the host check and get the response which contains the response key
        hcresp = self.hostChecker.doCheck(preauth, self.host)
        # set the response key as the new DSPREAUTH cookie value
        self.opener.setDspreauthCookie(self.host, hcresp[2])
        # set params needed to send the host check response key
        params = urllib.urlencode({'loginmode'  : 'mode_postAuth', 'postauth'  : 'state_%s' % stateid})
        self.updateSignInStatus('Sending host check response key')
        logging.debug('Sending preauth %s', params)
        resp = self.opener.open(self.loginurl, params)

        preauth = self.opener.getCookie('DSPREAUTH')
        if preauth is None:
            self.updateSignInStatus('Host check failed, no response to post auth key')
            logging.error('Host check failed, no preauth cookie in response to host check post auth')
            logging.debug("%s %s", url, resp)
            self.opener.printCookies()
            raise Exception('Host check failed, failed to get DSPREAUTH cookie')

        # send preauth cookie to host checker, not sure why this is needed
        self.hostChecker.sendCookie(preauth)
        return resp

    def signOut(self):
        self.updateSignInStatus('Signing out')
        resp = self.opener.open(self.logouturl)
        if not 'Your session has been terminated' in resp:
            self.updateSignInStatus('Sign out failed')
            # signout failed, maybe user no longer has network connection
            return False
        self.updateSignInStatus('Sign out succeeded')
        return True




import os
import urllib
import urlparse
import ssl
import logging
from datetime import datetime, timedelta

from lib.hostchecker import HostChecker
from lib.vpnopener import VpnOpener
from lib import sudo

logger = logging.getLogger(__name__)

class CookieDt:

    def __init__(self, elapsed):
        self.elapsed = elapsed
        self.cookiedt = datetime.fromtimestamp(0)

    def update(self, value):
        try:
            self.cookiedt = datetime.fromtimestamp(int(value))
        except:
            self.cookiedt = datetime.fromtimestamp(0)

    def isElapsed(self):
        return datetime.now() > (self.cookiedt + self.elapsed)

    def getStr(self):
        if self.cookiedt > datetime.fromtimestamp(0):
            return self.cookiedt.isoformat()
        else:
            return ""


class VpnWeb:
    """
    Performs web based transactions to the juniper web portal such as
    signing in/out and running host checker.
    """

    def __init__(self, ncPath, vpnstatus):
        self.ncPath = ncPath
        self.host = ""
        self.realm = ""
        self.port = 443
        self.baseurl = ""
        self.loginurl = ""
        self.welcomeurl = ""
        self.logouturl = ""
        self.homeurl = ""
        self.dsid = ""
        self.username = ""
        self.pin = ""
        self.token = ""

        self.vpnstatus = vpnstatus

        self.cookieDtFirst = CookieDt(timedelta(hours=24))
        self.cookieDtLast = CookieDt(timedelta(hours=1))

        # create vpn opener to handle https and cookie operations
        # cookie file will be stored in juniper directory
        self.opener = VpnOpener(os.path.join(self.ncPath, "jccl.txt"))

        self.hostChecker = HostChecker(os.path.join(self.ncPath, "tncc.jar"), os.path.join(self.ncPath, "narport.txt"))
        self.ncjar = os.path.join(self.ncPath, "ncLinuxApp.jar")

    def setConfig(self, host, port, urlnum, realm):
        self.host = host
        self.port = port
        self.baseurl = "https://%s:%i/dana-na/auth" % (host, port)
        self.loginurl = "%s/%s/login.cgi" % (self.baseurl, urlnum)
        self.welcomeurl = "%s/%s/welcome.cgi" % (self.baseurl, urlnum)
        self.logouturl = "%s/logout.cgi" % self.baseurl
        self.homeurl = "https://%s:%i/dana/home/index.cgi" % (host, port)
        self.realm = realm

    def setCredentials(self, username, pin, token):
        self.username = username
        self.pin = pin
        self.token = token

    def parseParams(self, text):
        params = {}
        for line in text.splitlines():
            if not "PARAM" in line:
                continue
            parts = line.split("\"")
            params[parts[1]] = parts[3]
        return params

    def isSignedIn(self):
        # there are several ways we determine if we are signed in
        # 1. no DSID cookie means not signed in
        #   DSID cookie is cleared when checking sign in
        #   and time is expired or have been idle too long or when signing out
        # 2. have DSID cookie but the time since we first signed in has elapsed
        #    the system will automatically sign you out after 24 hours (hard coded for now)
        #    regardless of idle time
        # 3. have DSID cookie, less than 24 hours since sign in, if host checker
        #    is running, we shouldn't be marked as "idle" and so should still be signed in
        #    if host checker isn't running then we see if it"s been an hour since last access
        #
        dsid = self.opener.getCookie("DSID")
        if dsid is None or len(dsid) < 32:
            return False
        else:
            if self.cookieDtFirst.isElapsed():
                return False
            if not self.hostChecker.isRunning() and self.cookieDtLast.isElapsed():
                return False
            return True

    def checkSignIn(self):
        """
        Accesses the vpn home index.cgi with current cookies.  If we are signed in, the DSLastAccess
        will be updated and the isSignedIn check will pass. If we are not signed in, the vpn
        will redirect us back to welcome.cgi and clear all the cookies including DSID.
        """
        logger.debug("Accessing home url %s", self.homeurl)
        resp = self.opener.open(self.homeurl)
        self.updateStatus()
        signedIn = self.isSignedIn()
        if not signedIn:
            logger.debug(resp)
        return signedIn

    def checkSignInAndError(self):
        try:
            if self.checkSignIn():
                return 0
            else:
                return -1
        except Exception as e:
            logger.exception(e)
            return -2

    def updateStatus(self, status=""):
        self.cookieDtFirst.update(self.opener.getCookie("DSFirstAccess"))
        self.cookieDtLast.update(self.opener.getCookie("DSLastAccess"))
        first = self.cookieDtFirst.getStr()
        last = self.cookieDtLast.getStr()
        hostCheck = self.hostChecker.isRunning()
        self.vpnstatus.setSignStatus(status, hostCheck, first, last, "", "")

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
        loginParams = urllib.urlencode({"username"  : username,
                                        "password"  : pin + token,
                                        "realm"     : self.realm,
                                        "pin"       : pin,
                                        "token"     : token})
        logger.debug("Signing in with parameters %s", loginParams.replace(pin, "*").replace(token, "*"))
        self.opener.printCookies()
        self.updateStatus("Signing In with username %s" % username)
        resp = self.opener.open(self.loginurl, loginParams)

        if "Invalid username or password" in resp:
            self.updateStatus("Sign in failed, invalid username or password")
            raise Exception("Invalid username or password, re-enter your information and try again")

        if "Host Checker" in resp:
            resp = self.checkHost(self.opener.request.geturl(), resp)

        # check for other login sessions after host check
        if "id=\"DSIDConfirmForm\"" in resp:
            logger.info("Found other active session, leaving it open and continuing")
            #formData = m/name="FormDataStr" value="([^"]+)"/
            formData = ""
            contParams = urllib.urlencode({"btnContinue":"Continue the session", "FormDataStr": formData})
            resp = self.opener.open(self.loginurl, contParams)
            logger.debug("%s", resp)
            self.opener.printCookies()

        self.dsid = self.opener.getCookie("DSID")
        if self.dsid is None:
            msg = "Sign in failed, DSID not found after host check"
            self.updateStatus(msg)
            logger.error(msg)
            logger.debug("%s", resp)
            self.opener.printCookies()
            raise Exception(msg)
        self.updateStatus("Sign in successful")
        logger.debug("Logged in and got DSID")

        # once logged in successfully, download and install
        # network connect components as needed
        self.installNc()

    def checkHost(self, url, resp):
        # How the host checker works
        # 1. After login, the returned page gives you parameters for the host checker and a state id
        # (via url redirection in the location header of the response) and also a preauth key
        # 2. The host checker is started with the parameters embedded in the login page
        # 3. The preauth key and host are sent to the host checker over a socket
        # 4. The host checker responds with a key to the preauth key
        # 5. The responded key is passed back to the vpn site along with some other parameters
        # 6. The vpn site responds back with a DSID needed to connect to the VPN

        # get params from resp to download and start host checker, params are in the form
        # <PARAM NAME="name" VALUE="5.0">
        params = self.parseParams(resp)

        # make sure the host checker jar is already downloaded
        if not self.hostChecker.exists():
            self.updateStatus("Downloading host checker")
            self.downloadHostChecker(params["DownloadPath"])
        if not self.hostChecker.exists():
            logger.error("Failed to download host checker")
            self.updateStatus("Failed to download host checker")
            raise Exception("Failed to download host checker")

        self.updateStatus("Running host checker")
        # make sure we got the preauth key
        preauth = self.opener.getCookie("DSPREAUTH")
        if preauth is None:
            self.updateStatus("Host check failed, missing  DSPREAUTH")
            logger.error("Preauth key not found in login response.")
            logger.debug("%s %s", url, resp)
            self.opener.printCookies()
            raise Exception("Host check failed, failed to get DSPREAUTH cookie")

        # get the state id and realm id from the new url returned from the login
        parsedParams = urlparse.parse_qs(url)
        stateid = parsedParams["id"][0].split("_")[1]
        signinRealmId = parsedParams["signinRealmId"][0]

        self.hostChecker.startHostChecker(params)
        # do the host check and get the response which contains the response key
        hcresp = self.hostChecker.doCheck(preauth, self.host)
        # set the response key as the new DSPREAUTH cookie value
        self.opener.setDspreauthCookie(self.host, hcresp[2])
        # set params needed to send the host check response key
        params = urllib.urlencode({"loginmode"  : "mode_postAuth", "postauth"  : "state_%s" % stateid})
        self.updateStatus("Sending host check response key")
        logger.debug("Sending preauth %s", params)
        resp = self.opener.open(self.loginurl, params)

        preauth = self.opener.getCookie("DSPREAUTH")
        if preauth is None:
            self.updateStatus("Host check failed, no response to post auth key")
            logger.error("Host check failed, no preauth cookie in response to host check post auth")
            logger.debug("%s %s", url, resp)
            self.opener.printCookies()
            raise Exception("Host check failed, failed to get DSPREAUTH cookie")

        # send preauth cookie to host checker, not sure why this is needed
        self.hostChecker.sendCookie(preauth)
        return resp

    def downloadHostChecker(self, downloadUrl):
        fullUrl = "https://%s:%s%s" % (self.host, self.port, downloadUrl)
        logger.debug("downloading host checker from url %s", fullUrl)
        resp = self.opener.open(fullUrl)
        with open(self.hostChecker.jar, "w") as hcf:
            hcf.write(resp)

    def signOut(self):
        self.updateStatus("Signing out")
        resp = self.opener.open(self.logouturl)
        if not "Your session has been terminated" in resp:
            self.updateStatus("Sign out failed")
            # signout failed, maybe user no longer has network connection
            return False
        self.hostChecker.stopHostChecker()
        self.opener.open(self.welcomeurl)
        self.updateStatus("Sign out succeeded")
        return True

    def installNc(self):
        if not os.path.exists(self.ncjar):
            self.updateStatus("Downloading NC")
            self.downloadClient()
        if not os.path.exists(self.ncjar):
            self.updateStatus("Failed to download NC")
            return

        try:
            self.updateStatus("Installing NC")
            install = sudo.Sudo("/opt/juniper-gui/network_connect/installnc.sh " + self.ncjar, "", "Input password for installing network connect", True)
            install.execute()
            self.updateStatus("NC Installed")
        except:
            self.updateStatus("Failed to install NC")
            raise Exception("Failed to install Network Connect client")

    def downloadClient(self):
        fullUrl = "https://%s:%s%s" % (self.host, self.port, "/dana-cached/nc/ncLinuxApp.jar")
        logger.debug("downloading client from url %s", fullUrl)
        resp = self.opener.open(fullUrl)
        with open(self.ncjar, "w") as ncf:
            ncf.write(resp)


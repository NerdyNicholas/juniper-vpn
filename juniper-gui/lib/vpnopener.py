
import urllib2
import cookielib
import logging
import os
import ssl

logger = logging.getLogger(__name__)

class VpnOpener:
    """
    Class to perform https requests with cookies to the vpn web portal.
    """

    def __init__(self, cookieFile, agent=None):
        self.request = None
        self.resp = ""
        self.cookieFile = cookieFile
        self.timeout = 30
        if agent is None:
            agent = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:48.0) Gecko/20100101 Firefox/48.0'
        # create cookie jar to use with opener
        self.cjar = cookielib.LWPCookieJar(filename=cookieFile)
        if os.path.exists(cookieFile):
            self.cjar.load()

        # create ssl opener with our cookie jar to be used for all the web based interactions
        self.opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ssl._create_unverified_context()), urllib2.HTTPCookieProcessor(self.cjar))
        self.opener.addheaders = [('User-agent', agent)]

    def getCookie(self, name):
        for cookie in self.cjar:
            if cookie.name == name:
                return cookie.value
        return None

    def printCookies(self):
        for cookie in self.cjar:
            logger.info('%s = %s', cookie.name, cookie.value)

    def setupLoginCookies(self, host):
        # not sure if the sel_auth cookie is needed, but set it here since browser does
        cookie = cookielib.Cookie(version=0, name='sel_auth', value='otp', port=None, port_specified=False,
                                    domain=host, domain_specified=False, domain_initial_dot=False, path='/',
                                    path_specified=True, secure=False, expires=None, discard=True,
                                    comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        self.cjar.set_cookie(cookie)

        # set cookie for DSCheckBrowser to java so vpn site will give us host check parameters for java host checker
        cookie = cookielib.Cookie(version=0, name='DSCheckBrowser', value='java', port=None, port_specified=False,
                                    domain=host, domain_specified=False, domain_initial_dot=False, path='/',
                                    path_specified=True, secure=False, expires=None, discard=True, comment=None,
                                    comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        self.cjar.set_cookie(cookie)

    def setDspreauthCookie(self, host, value):
        cookie = cookielib.Cookie(version=0, name='DSPREAUTH', value=value, port=None, port_specified=False,
                                    domain=host, domain_specified=False, domain_initial_dot=False, path='/dana-na/',
                                    path_specified=True, secure=False, expires=None, discard=True, comment=None,
                                    comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        self.cjar.set_cookie(cookie)

    def open(self, url, params=None):
        self.request = self.opener.open(url, params, timeout=self.timeout)
        self.resp = self.request.read()
        self.cjar.save()
        return self.resp


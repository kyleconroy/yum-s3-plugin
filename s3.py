"""
Yum plugin for Amazon S3 access.

This plugin provides access to a protected Amazon S3 bucket using either boto
or Amazon's REST authentication scheme.

On CentOS this file goes into /usr/lib/yum-plugins/s3.py

You will also need two configuration files.   See s3.conf and s3test.repo for
examples on how to deploy those.


"""
#   Copyright 2011, Robert Mela
#   Copyright 2011, Jens Braeuer
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import logging
import os
import sys
import urllib
import urllib2
import time
import sha
import hmac
import base64
import yum.Errors
from yum.plugins import TYPE_CORE, TYPE_INTERACTIVE
from yum.yumRepo import YumRepository
from yum import config
from yum import logginglevels


def authenticate(url, access_key, secret_key, expires=None):
    """Sign an url for AWS authentication.
    Assumses GET and no query parameters."""
    expires = expires or int(time.time()) + 40
    bucket = url.replace('.s3.amazonaws.com', '').replace('http:/', '')
    sigstring = "GET\n\n\n%s\n%s" % (expires, bucket)
    h = hmac.new(secret_key, sigstring, sha)
    query = [
        ('AWSAccessKeyId', access_key),
        ('Expires', expires),
        ('Signature', base64.encodestring(h.digest()).strip()),
    ]
    return url + '?' + urllib.urlencode(query, True)


class Opener(urllib.FancyURLopener):
    def http_error_default(self, url, fp, errcode, errmsg, headers):
        msg = "HTTP %d %s: %s" % (errcode, errmsg, url)
        raise yum.Errors.YumDownloadError(msg)


class UrllibGrabber(object):
    logger = logging.getLogger("yum.verbose.main")

    def __init__(self, aws_access_key, aws_secret_key, baseurl):
        try:
            baseurl = baseurl.pop(0)
        except AttributeError:
            pass
        self.opener = Opener()
        self.baseurl = baseurl
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key

    def auth(self, url):
        return authenticate("%s%s" % (self.baseurl, url),
                            self.aws_access_key, self.aws_secret_key)

    def urlgrab(self, url, filename, **kwargs):
        """urlgrab(url) copy the file to the local filesystem"""
        url = self.auth(url)
        self.logger.debug("urlgrab url=%s filename=%s" % (url, filename))
        filename, headers = self.opener.retrieve(url, filename)
        return filename

    def urlopen(self, url, **kwargs):
        """urlopen(url) open the remote file and return a file object"""
        return urllib2.urlopen(self.auth(url))

    def urlread(self, url, limit=None, **kwargs):
        """urlread(url) return the contents of the file as a string"""
        return urllib2.urlopen(self.auth(url)).read()


class AmazonS3Repo(YumRepository):
    """
    Repository object for Amazon S3.
    """

    def __init__(self, repoid):
        YumRepository.__init__(self, repoid)
        self.enable()
        self.grabber = None

    def _getFile(self, *args, **kwargs):
        """Authenticate the package URL."""
        url = kwargs['url'] + '/' + kwargs['relative']
        url = authenticate(url, self.key_id, self.secret_key)
        kwargs['relative'] = url.replace(kwargs['url'] + '/', '')
        return YumRepository._getFile(self, *args, **kwargs)

    def _getgrabfunc(self):
        raise Exception("get grabfunc!")

    def _getgrab(self):
        if not self.grabber:
            self.grabber = UrllibGrabber(self.key_id, self.secret_key,
                                         self.baseurl)
        return self.grabber

    grabfunc = property(lambda self: self._getgrabfunc())
    grab = property(lambda self: self._getgrab())


__revision__ = "1.0.0"
requires_api_version = '2.5'
plugin_type = (TYPE_CORE, TYPE_INTERACTIVE)


def config_hook(conduit):
    logger = logging.getLogger("yum.verbose.main")
    config.RepoConf.s3_enabled = config.BoolOption(False)
    config.RepoConf.key_id = config.Option() or \
        conduit.confString('main', 'aws_access_key_id')
    config.RepoConf.secret_key = config.Option() or \
        conduit.confString('main', 'aws_secret_access_key')

    parser = conduit.getOptParser()
    parser.add_option('', '--public-repos', dest='allowpublic',
                      action='store_true', default=False,
                      help="Consult the public yum repos")


def prereposetup_hook(conduit):
    """Remove repos that aren't S3 enabled."""
    repos = conduit.getRepos()
    opts, commands = conduit.getCmdLine()

    for key,repo in repos.repos.copy().iteritems():
        if not isinstance(repo, AmazonS3Repo) and not opts.allowpublic:
            repos.delete(repo.id)


def init_hook(conduit):
    """
    Plugin initialization hook. Setup the S3 repositories.
    """

    repos = conduit.getRepos()
    conf = conduit.getConf()
    cachedir = conduit.getConf().cachedir

    for key,repo in repos.repos.iteritems():
        if isinstance(repo, YumRepository) and repo.s3_enabled:
            new_repo = AmazonS3Repo(key)
            new_repo.name = repo.name
            new_repo.baseurl = repo.baseurl
            new_repo.mirrorlist = repo.mirrorlist
            new_repo.basecachedir = repo.basecachedir
            new_repo.gpgcheck = repo.gpgcheck
            new_repo.gpgkey = repo.gpgkey
            new_repo.proxy = repo.proxy
            new_repo.enablegroups = repo.enablegroups
            new_repo.key_id = repo.key_id
            new_repo.secret_key = repo.secret_key
            if hasattr(repo, 'priority'):
                new_repo.priority = repo.priority
            if hasattr(repo, 'base_persistdir'):
                new_repo.base_persistdir = repo.base_persistdir

            repos.delete(repo.id)
            repos.add(new_repo)

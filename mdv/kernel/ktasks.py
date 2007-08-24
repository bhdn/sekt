#!/usr/bin/python

#TODO use yaml as configuration source
#TODO move all string constants to configuration

import sys
import os
import optparse
import shelve
import re
import urllib
import logging
import zipfile

from cStringIO import StringIO
from xml.etree import ElementTree

# external deps:

import yaml
import bugz

CONFIG_DEFAULTS = """\
cve_source: data/cve.zip
ticket_cache: data/ticket-cache.shelve
conf:
    path_environment: KTASKS_CONF
    user_file: .ktasks
"""

log = logging.getLogger("ktasks")

class Error(Exception):
    pass

class TicketError(Error):
    pass

class UnknownTicket:
    pass


def mergeconf(base, another):
    baset = type(base)
    merged = another
    if baset is dict:
        merged = base.copy()
        for k, v in another.iteritems():
            try:
                basev = base[k]
            except KeyError:
                merged[k] = v
            else:
                merged[k] = mergeconf(basev, v)
    elif baset is list:
        merged = another[::]
        merged.extend(another)
    return merged


class ConfWrapper:

    _conf = None
    
    def __init__(self, conf):
        self._conf = conf

    def __getattr__(self, name):
        val = self._conf[name]
        if type(val) is dict:
            return ConfWrapper(val)
        return val

    def __getitem__(self, name):
        return self._conf[name]


class Config(ConfWrapper):

    _conf = None
    raw_defaults = CONFIG_DEFAULTS
    options = None
    args = None

    def __init__(self, defaults=None):
        if defaults is None:
            self.parse(self.raw_defaults)
        else:
            self.merge(defaults)

    def merge(self, data):
        self._conf = mergeconf(self._conf, data)

    def parse(self, raw):
        data = yaml.load(raw)
        self.merge(data)

    def load(self, path):
        """Load the configuration file in the given path"""
        raw = open(path).read()
        self.parse(raw)

    def __repr__(self):
        return "<Config %s>" % self._conf


class TicketCache:

    def __init__(self, path):
        self.path = path
        self._shelf = None
        self._cache = {}
        self.load()

    def load(self):
        log.info("opening shelf at %s" % self.path)
        self._shelf = shelve.open(self.path)

    def get(self, bugid):
        try:
            return self._cache[bugid]
        except KeyError:
            try:
                ticket = self._shelf[bugid]
                self._cache[bugid] = ticket
                log.info("ticket cache hit for %s" % bugid)
                return ticket
            except KeyError:
                log.info("ticket cache miss for %s"  % bugid)
                raise UnknownTicket

    def add(self, ticket):
        self._shelf[ticket.bugid] = ticket
        self._shelf.sync()
        self._cache[ticket.bugid] = ticket

    def close(self):
        self._shelf.close()

def fetch_url(url):
    """Small layer just to allow further enhacements"""
    log.info("fetching URL: %s" % url)
    return urllib.urlopen(url).read()


class CVESource:

    def __init__(self, dbpath):
        self.root = "./tree"
        self.dbpath = dbpath
        self._zipfile = zipfile.ZipFile(dbpath, "r")

    def _get_path(self, cveid):
        cve_, year, number = cveid.split("-")
        return os.path.join(self.root, year, number[:2], cveid)

    def _get_xml(self, cveid):
        path = self._get_path(cveid)
        raw = self._zipfile.read(path)
        xml = ElementTree.parse(StringIO(raw))
        return xml

    def _get_cve_from_xml(self, xml):
        return CVE.from_mitre_xml(xml)

    def get(self, cveid):
        xml = self._get_xml(cveid)
        cve = self._get_cve_from_xml(xml)
        return cve


class CVE:

    class NoDescriptionYet:
        pass

    cveid = None
    references = None
    description = None
    status = None
    phase = None

    def __init__(self, cveid):
        self.cveid = cveid

    @classmethod
    def from_mitre_xml(klass, xml):
        root = xml.getroot()
        cveid = root.attrib["name"]
        cve = CVE(cveid) #FIXME we already have cveid!
        node = root.find(".//status")
        if node is not None: # damn bool()!
            cve.status = node.text
        node = root.find(".//phase")
        if node is not None:
            cve.phase = node.text
        cve.description = root.find(".//desc").text
        cve.references = [{
                "source": ref.attrib.get("source"),
                "url": ref.attrib.get("url"),
                "descr": ref.text }
            for ref in root.findall(".//refs/ref")]
        # don't parse comments, as apparently we wont' need them
        return cve


class SecurityTicket:
    """Specialized wrapper for the bugz.Ticket class.
    
    It provides all the CVE related data from one ordinary ticket.
    """
    
    _ticket = None
    cveid = None
    cve = None
    release_status = None

    def __init__(self, ticket, cvesource):
        self._ticket = ticket
        self._parse_ticket(cvesource)

    def _parse_ticket(self, cvesource):
        #TODO move this regexp to configuration
        cvere = r"SECURITY +ADVISORY:? +(?P<cve>CVE-....-....)"
        found = re.search(cvere, self.title)
        if found is None:
            raise TicketError, "bad ticket title: %r, must match %s" % \
                    (self.title, cvere)
        self.cveid = found.group("cve")
        self.cve = cvesource.get(self.cveid)
        self.release_status = []
        # example: "CS3.0: INVALID | 2006.0: OPEN | 2007.0: FIXED"
        expr = r"^ *([^ :]+): *([A-Z]+)(?: *\| *([^ ]+): *([A-Z]+))*$"
        statusre = re.compile(expr, re.MULTILINE)
        for comment in self.comments:
            found = statusre.search(comment["what"])
            if found:
                line = found.group()
                pairs = line.split("|")
                status = dict((k.strip(), v.strip()) for k, v in
                    (pair.split(":") for pair in pairs))
                self.release_status.append(status)

    def __getattr__(self, name):
        return getattr(self._ticket, name)


class TicketSource:

    def __init__(self, cvesource, cachepath, base="https://qa.mandriva.com"):
        self.cvesource = cvesource
        self._bugz = bugz.Bugz(base, always_auth=True)
        self._cache = TicketCache(cachepath)

    def search(self, query):
        found = self._bugz.search(query)
        for entry in found:
            bugid = entry["bugid"]
            ticket = self.get(bugid)
            yield ticket

    def security_tickets(self):
        for ticket in self.search("ADVISORY:"):
            yield SecurityTicket(ticket, self.cvesource)

    def get(self, bugid):
        try:
            return self._cache.get(bugid)
        except UnknownTicket:
            ticket = self._bugz.get(bugid)
            self._cache.add(ticket)
            return ticket


class KTasks:

    def __init__(self, config):
        self.config = config
        self.cvesource = CVESource(config.cve_source)
        self.ticketsource = TicketSource(self.cvesource,
                config.ticket_cache)

    def easy_tickets(self):
        for ticket in self.ticketsource.security_tickets():
            pass

def parse_options(args):
    def parse_option(option, opt_str, value, parser, *args, **kwargs):
        kv = value.split("=", 1)
        if len(kv) != 2:
           raise optparse.OptionValueError, "-o accepts values only in "\
                   "the name=value form"
        levels = kv[0].split(".")
        lastv = kv[1]
        for name in levels[:0:-1]:
            lastv = {name: lastv}
        parser.values.config_options[levels[0]] = lastv
    parser = optparse.OptionParser("ktasks")
    parser.set_defaults(config_options={})
    parser.add_option("-e", "--easy-tickets", action="store_true",
            default=False, help="show easy to fix tickets")
    parser.add_option("-o", "--option", type="string", action="callback",
            callback=parse_option,
            help="set one configuration option in the form opt=val")
    parsed = parser.parse_args(args)
    return parsed

def main():
    options, args = parse_options(sys.argv)
    config = Config()
    config.merge(options.config_options)
    path = (os.environ.get(config.conf.path_environment) or
            os.path.expanduser(os.path.join("~", config.conf.user_file)))
    if os.path.exists(path):
        config.load(path)
    ktasks = KTasks(config)
    if options.easy_tickets:
        pass

if __name__ == "__main__":
    main()

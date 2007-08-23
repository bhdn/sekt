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

import bugz

log = logging.getLogger("ktasks")

class Error(Exception):
    pass

class TicketError(Error):
    pass

class UnknownTicket:
    pass


class Config:

    def __init__(self, options, args):
        self.options = options
        self.args = args


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

    def __init__(self, options, config):
        self.options = options
        self.config = config
        self.cvesource = CVESource(options.cve_source)
        self.ticketsource = TicketSource(self.cvesource,
                config.ticket_cache)

    def easy_tickets(self):
        for ticket in self.ticketsource.security_tickets():
            pass

def parse_options(args):
    parser = optparse.OptionParser("ktasks")
    parser.add_option("-e", "--easy-tickets", action="store_true",
            default=False, help="show easy to fix tickets")
    parser.add_options("--cve-source", type="string",
            default="/home/bogdano/teste/kernel/CVEs/database/tree.zip",
            help="the zip archive containing all the CVEs")
    parser.add_options("--ticket-cache", type="string",
            default="/home/bogdano/teste/kernel/CVEs/database/ticket-cache.shelf",
            help="shelve store containing a local tickets cache")
    parsed = parser.parse_args(args)
    return parsed

def main(args):
    options, args = parse_options(args)
    config = Config(options)
    ktasks = KTasks(options)
    if options.easy_tickets:
        pass

if __name__ == "__main__":
    main(sys.argv)

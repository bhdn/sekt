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

import bugz

log = logging.getLogger("ktasks")

class Error(Exception):
    pass

class TicketError(Error):
    pass

class UnknowTicket:

    pass


class TicketCache:

    def __init__(self, path):
        self.path = path
        self._load()

    def load(self):
        pass

    def get_ticket(self, number):
        raise UnknowTicket

    def add_ticket(self, ticket):
        pass

    def save(self):
        pass


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
        xml = self._zipfile.read(path)
        return xml

    def _get_cve_from_xml(self, xml):
        return CVE.from_mitre_xml(xml)

    def get_cve(self, cveid):
        xml = self._get_xml(cveid)
        cve = self._get_cve_from_xml(xml)


class CVE:

    class NoDescriptionYet:
        pass

    cveid = None
    references = None
    description = None
    phase = None

    def __init__(self, cveid):
        self.cveid = cveid

    @classmethod
    def from_mitre_xml(klass, xml):
        root = xml.getroot()
        cveid = root.attrib["name"]
        cve = CVE(cveid) #FIXME we already have cveid!
        cve.description = root.find(".//desc").text
        cve.references = [{
                "source": ref.attrib.get("source"),
                "url": ref.attrib.get("url"),
                "descr": ref.text }
            for ref in root.findall(".//refs/ref")]
        # don't parse comments, as apparently we wont' need them
        cve.phase = root.find(".//phase").text
        return cve


class SecurityTicket(Ticket):

    cve = None
    url = None
    valid = None
    release_status = None

    def __init__(self, ):
        Ticket.__init__(self, *args, **kwargs)
        self._parse_ticket()

    def _parse_ticket(self):
        #TODO move this regexp to configuration
        cvere = r"SECURITY\s+ADVISORY:?\s+(?P<cve>CVE-....-....)"
        found = re.match(cvere, self.title)
        if found is None:
            raise TicketError, "bad ticket title: %r, must match %s" % \
                    (self.title, cvere)
        self.cveid = found.group("cve")
        self.


    def __getattr__(self, name):
        return getattr(self._ticket, name)


class TicketSource:

    def __init__(self, config):
        self.config = config

    def search(self, ):
        pass

    def _make_ticket(self):
        pass

    def _get_security_tickets(self):
        for ticket in self.search("ADVISORY:"):
            yield SecurityTicket(ticket)


class KTasks:

    def __init__(self, options, config):
        self.options = options
        self.config = config

    def easy_tickets(self):
        for ticket in self._get_security_tickets():
            pass

    def _get_security_tickets(self):
        pass

def parse_options(args):
    parser = optparse.OptionParser("ktasks")
    parser.add_option("-e", "--easy-tickets", action="store_true",
            default=False, help="show easy to fix tickets")
    parsed = parser.parse_args(args)
    return parsed

def main(args):
    options, args = parse_options(args)

    if options.easy_tickets:
        pass
    elif:
        pass

if __name__ == "__main__":
    main(sys.argv)

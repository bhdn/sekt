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
import bsddb

from cStringIO import StringIO
from xml.etree import ElementTree

# external deps:

import yaml
import bugz

CONFIG_DEFAULTS = """\
cve_source: data/cve.zip
ticket_cache: data/ticket-cache.shelve
bugzilla_base_url: https://qa.mandriva.com
cve:
    valid_status:
        - OPEN
        - NEW
        - INVALID
        - FIXED
        - RELEASED
        - WONTFIX
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

class CANTicket(TicketError):
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
        merged = base[::]
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


class CVEPool:

    def __init__(self, dbpath):
        self.dbpath = dbpath
        log.info("opening cve archive at %s" % self.dbpath)
        self._db = bsddb.btopen(dbpath)

    def _get_xml(self, cveid):
        xml = self._db.get(cveid)
        return xml

    @classmethod
    def _get_cve(klass, xml):
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

    def get(self, cveid):
        xml = self._get_xml(cveid)
        cve = self._get_cve(xml)
        return cve

    def put(self, cveid, xml):
        self._db[cveid] = xml

    def close(self):
        log.debug("closing cve archive at %s" % self.dbpath)
        self._db.save()
        self._db.close()


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


class SecurityTicket:
    """Specialized wrapper for the bugz.Ticket class.
    
    It provides all the CVE related data from one ordinary ticket.
    """
    
    _ticket = None
    cveid = None
    cve = None
    release_status = None

    def __init__(self, ticket, cvesource, config):
        self._ticket = ticket
        self._parse_ticket(cvesource, config)

    def _parse_ticket(self, cvesource, config):
        #TODO move this regexp to configuration
        cvere = r"SECURITY +ADVISORY:? +(?P<cve>(?P<kind>CVE|CAN)-....-....)"
        found = re.search(cvere, self.title)
        if found is None:
            raise TicketError, "bad ticket title: %r, must match %s" % \
                    (self.title, cvere)
        kind = found.group("kind")
        if kind == "CAN":
            # exception: we don't have CAN data in our database, complain
            # about it
            raise CANTicket
        self.cveid = found.group("cve")
        self.cve = cvesource.get(self.cveid)
        self.release_status = self._find_release_status(config, self.comments)

    @classmethod
    def _find_release_status(klass, config, comments):
        # example: "CS3.0: INVALID | 2006.0: OPEN | 2007.0: FIXED"
        release_status = []
        valid = "|".join(config.cve.valid_status)
        expr = r"(?P<line>[^\s:]+: (?:%s)(?: \| [^ ]+: (?:%s))*)" % (valid,
                valid)
        statusre = re.compile(expr)
        for comment in comments:
            found = statusre.search(comment["what"])
            if found:
                line = found.group()
                pairs = line.split("|")
                status = dict((k.strip(), v.strip()) for k, v in
                    (pair.split(":") for pair in pairs))
                release_status.append(status)
        return release_status

    def __getattr__(self, name):
        return getattr(self._ticket, name)


class TicketSource:

    def __init__(self, cvesource, cachepath, base, config):
        self.cvesource = cvesource
        self._bugz = bugz.Bugz(base, always_auth=True)
        self._cache = TicketCache(cachepath)
        self.config = config

    def search(self, query):
        found = self._bugz.search(query)
        for entry in found:
            bugid = entry["bugid"]
            ticket = self.get(bugid)
            yield ticket

    def security_tickets(self):
        for ticket in self.search("ADVISORY:"):
            try:
                yield SecurityTicket(ticket, self.cvesource, self.config)
            except CANTicket:
                log.warn("can't parse CAN entry from ticket %s, "\
                        "skipping it" % ticket.bugid)

    def get(self, bugid):
        try:
            return self._cache.get(bugid)
        except UnknownTicket:
            ticket = self._bugz.get(bugid)
            self._cache.add(ticket)
            return ticket

    def close(self):
        self._cache.close()


class SecteamTasks:

    class Reasons:
        class HasCommits:
            pass
        class HasChangeLogEntry(HasCommits):
            pass

    def __init__(self, config):
        self.config = config
        self.cvesource = CVESource(config.cve_source)
        self.ticketsource = TicketSource(self.cvesource,
                config.ticket_cache, config.bugzilla_base_url, config)

    def easy_tickets(self):
        """Points those tickets that (apparently) can be easily fixed.

        Those tickets considered "easy" are usually:

        - those that have the git commit URL in the references section of
          the CVE
        - or have pointers to the changelog containing the commit (harder
          to find the right commit)

        @return: generator with tuples of (ticket, [(reason, *args), ...])
        """
        gitbase = "git/"
        for ticket in self.ticketsource.security_tickets():
            if ticket.resolution:
                continue
            for ref in ticket.cve.references:
                url = ref.get("url")
                if url: 
                    reasons = []
                    if gitbase in url:
                        reasons.append((self.Reasons.HasCommits, url))
                    if "ChangeLog-2." in url:
                        reasons.append((self.Reasons.HasChangeLogEntry, url))
                    if reasons:
                        yield (ticket, reasons)

    def status(self):
        """Shows the status for each ticket, and each distro.

        @return: a sequence of (ticket, last_status) tuples.
                 last_status being a dict of DISTRO: STATUS pairs.
        """
        for ticket in self.ticketsource.security_tickets():
            if not ticket.release_status:
                status = None
            else:
                status = ticket.release_status[-1]
            yield (ticket, status)

    def finish(self):
        self.cvesource.close()
        self.ticketsource.close()

class Interface:
    def __init__(self, config, ktasks):
        self.config = config
        self.ktasks = ktasks

    def easy_tickets(self):
        for ticket, reasons in self.ktasks.easy_tickets():
            print "%s %s" % (ticket.bugid, ticket.cve.cveid)
            for reason in reasons:
                if issubclass(reason[0], self.ktasks.Reasons.HasCommits):
                    print "   ", reason[1]

    def status(self):
        for ticket, status in self.ktasks.status():
            if status is None:
                line = "NO STATUS"
            else:
                line = " | ".join("%s: %s" % (k, v) for k, v in
                        status.iteritems())
            print "%s %s: %s" % (ticket.bugid, ticket.cve.cveid, line)
            



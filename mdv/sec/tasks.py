#!/usr/bin/env python

import sys
import os
import time
import logging
from cStringIO import StringIO
import ConfigParser

# external deps:

#import yaml
#import bugz

# yes, I hate high import times:

def yaml():
    import yaml
    return yaml

def bugz():
    import bugz
    return bugz

CONFIG_DEFAULTS = """\
[sekt]
workdir = ~/sekt/
cve_database = cves
cve_info = cves-metadata.shelve
bugzilla_base_url = https://qa.mandriva.com

[cve]
valid_status = OPEN NEW INVALID FIXED RELEASED WONTFIX

[conf]
path_environment = SEKT_CONF
user_file = .sekt
"""

log = logging.getLogger("sekt")

class Error(Exception):
    pass

class TicketError(Error):
    pass

class InvalidCVE(Error):
    pass

class UnknownTicket:
    pass

class CANTicket(TicketError):
    pass

class PullError(Error):
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

    _config = None

    def __init__(self, config, section=None):
        self._config = config
        self._section = section

    def __getattr__(self, name):
        if self._section is None:
            return ConfWrapper(self._config, name)
        val = self._config.get(self._section, name)
        return val

    def __repr__(self):
        output = StringIO()
        self._config.write(output)
        return output.getvalue()

class Config(ConfWrapper):

    raw_defaults = CONFIG_DEFAULTS
    _section = None
    _config = None

    def __init__(self, defaults=None):
        self._config = ConfigParser.ConfigParser(defaults=defaults)
        if defaults is None:
            self.parse(self.raw_defaults)

    def merge(self, data):
        self._conf = mergeconf(self._conf, data)

    def parse(self, raw):
        self._config.readfp(StringIO(raw))

    def load(self, path):
        """Load the configuration file in the given path"""
        self._config.read(path)

class CVEPool:

    def __init__(self, dbpath, infopath):
        self.dbpath = dbpath
        self.infopath = infopath
        log.info("opening cve archive at %s", self.dbpath)
        if not os.path.exists(dbpath):
            os.mkdir(dbpath)
        self._info = None # metadata is loaded lazily
        self._cvere = None

    def open(self):
        import shelve
        log.info("opening cve metadata at %s", self.infopath)
        self._info = shelve.open(self.infopath)
        self.open = lambda: None # hihihihi...

    @classmethod
    def _get_cve(klass, rawxml):
        from xml.etree import ElementTree
        xml = ElementTree.parse(StringIO(rawxml))
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
        return self.from_yaml(self.get_dump(cveid))

    def get_dump(self, cveid):
        path = self._path(cveid)
        try:
            rawyaml = open(path).read()
        except IOError:
            return None
        return rawyaml

    def find_cve(self, cveid, dump=False):
        import glob
        cveid = self._fix_prepend(cveid)
        expr = "%s/*/%s*" % (self.dbpath, cveid)
        for path in glob.iglob(expr):
            rawyaml = open(path).read()
            if dump:
                yield rawyaml
            else:
                yield self.from_yaml(rawyaml)

    @classmethod
    def from_yaml(klass, rawyaml):
        cve = CVE(None)
        cve.__dict__.update(yaml().parse(rawyaml))
        return cve

    def _fix_prepend(self, cveid):
        if not (cveid.startswith("CVE-") or cveid.startswith("CAN-")):
            cveid = "CVE-" + cveid
        return cveid

    def _path(self, cveid):
        cveid = self._fix_prepend(cveid)
        try:
            _, y, _ = cveid.split("-", 2)
        except ValueError:
            raise InvalidCVE, "invalid CVE ID: %s" % cveid
        path = os.path.join(self.dbpath, y, cveid)
        return path

    def _get_info(self, cveid):
        self.open()
        rawinfo = self._info.get(cveid)
        if rawinfo is not None:
            try:
                hash, changed = rawinfo
            except ValueError:
                hash = changed = None
            info = {"hash": hash, "changed": changed}
            return info

    def _set_info(self, cveid, hash=None, changed=None):
        self.open()
        rawinfo = (hash, changed)
        self._info[cveid] = rawinfo

    def _get_cve_regexp(self):
        import re
        self._re = re.compile("name=\"(?P<name>CVE-....-....)\"")
        self._get_cve_regexp = lambda: self._re
        return self._re

    def _get_id(self, xml):
        found = self._get_cve_regexp().search(xml)
        if found is not None:
            return found.group("name")
        raise PullError, "invalid CVE XML chunk: %s" % xml

    def put_xml(self, xml):
        import hashlib
        md5 = hashlib.md5()
        md5.update(xml)
        newhash = md5.hexdigest()
        cveid = self._get_id(xml)
        info = self._get_info(cveid)
        if info and info["hash"] == newhash:
            log.debug("no need to update %s (%s)", cveid, newhash)
        else:
            cve = self._get_cve(xml)
            rawyaml = repr(cve)
            path = self._path(cve.cveid)
            dir = os.path.dirname(path)
            if not os.path.exists(dir):
                os.mkdir(dir)
            import tempfile
            f = tempfile.NamedTemporaryFile(dir=dir, delete=False)
            f.write(rawyaml)
            f.close()
            os.rename(f.name, path)
            self._set_info(cveid, hash=newhash, changed=time.time())

    def close(self):
        log.debug("closing cve archive at %s" % self.dbpath)
        self._info.close()

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

    def __repr__(self):
        return yaml().dump(self.__dict__, default_flow_style=False)

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

class Paths:

    def __init__(self, config):
        self.config = config

    def _config_path(self, path):
        return os.path.expanduser(path)

    def _workdir_file(self, name_or_path):
        return os.path.join(self.workdir(),
                self._config_path(name_or_path))

    def workdir(self):
        return self._config_path(self.config.sekt.workdir)

    def cve_database(self, tmp=False):
        if tmp:
            return self.cve_database() + ".tmp"
        return self._workdir_file(self.config.sekt.cve_database)

    def cve_info(self):
        return self._workdir_file(self.config.sekt.cve_info)

class SecteamTasks:

    class Reasons:
        class HasCommits:
            pass
        class HasChangeLogEntry(HasCommits):
            pass

    def __init__(self, config):
        self.config = config
        self.paths = Paths(config)
        self.cves = None
        self.tickets = None

    def open_stuff(self):
        self.cves = CVEPool(self.paths.cve_database(),
                self.paths.cve_info())
        #self.tickets = TicketSource(self.cvesource,
        #        self.config.ticket_cache, self.config.bugzilla_base_url,
        #        self.config)

    def pull_cves(self, stream):
        """Pull CVE XMLs from a text stream (usually the one from
        cve.mitre.org)
        """
        from mdv.sec.pullcves import split
        cves = CVEPool(self.paths.cve_database(), self.paths.cve_info())
        for i, chunk in enumerate(split(stream)):
            if i % 100 == 0:
                yield True
            cves.put_xml(chunk)
        cves.close()

    def init(self):
        path = self.paths.workdir()
        if os.path.exists(path):
            return False
        log.info("created %s", path)
        os.mkdir(path)
        return True

    def dump_cve(self, cveid):
        self.open_stuff()
        dump = self.cves.get_dump(cveid)
        return dump

    def find_cve(self, cveid, dump=False):
        self.open_stuff()
        return self.cves.find_cve(cveid, dump)

    def finish(self):
        if self.cves:
            self.cves.close()
        if self.tickets:
            self.tickets.close()

class Interface:
    def __init__(self, config, tasks):
        self.config = config
        self.tasks = tasks

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

    def pull_cves(self):
        show = os.isatty(1)
        for _ in self.tasks.pull_cves(sys.stdin):
            if show:
                sys.stdout.write(".")
                sys.stdout.flush()

    def init(self):
        if self.tasks.init():
            print "done"
        else:
            print "already initialized"

    def dump_conf(self):
        print repr(self.config)

    def dump_cve(self, options):
        try:
            dump = self.tasks.dump_cve(options.cve)
        except InvalidCVE:
            dump = None
        if dump is None:
            try:
                found = self.tasks.find_cve(options.cve, dump=True)
                if os.isatty(1):
                    import subprocess
                    p = subprocess.Popen(["less"], stdin=subprocess.PIPE)
                    try:
                        for dump in found:
                            p.stdin.write(dump)
                            p.stdin.write("\n")
                    finally:
                        p.stdin.close()
                        p.wait()
                else:
                    sys.stdout.writelines(found)
            except IOError, e:
                if e.errno != 32: # broken pipe
                    raise
        else:
            if dump:
                print dump
            else:
                sys.stderr.write("no such identifier: %s\n" % options.cve)
                sys.exit(1)

#!/usr/bin/env python

import sys
import os
import time
import math
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
packages_database = packages.sqlite
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

class PackageError(Error):
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

    def medias(self):
        from mdv.hdlist import MediaInfo
        for section in self._config.sections():
            fields = section.split()
            if len(fields) != 2 or fields[0] != "distro":
                continue
            distro = fields[1]
            for option in self._config.options(section):
                media = MediaInfo()
                rawconf = self._config.get(section, option)
                conffields = rawconf.split(None, 2)
                if not conffields:
                    continue
                path = conffields[0]
                if len(conffields) == 2:
                    hdlist = conffields[1]
                else:
                    hdlist = "media_info/synthesis.hdlist.cz"
                media.hdlist = os.path.join(path, hdlist)
                media.name = option
                yield media, distro

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
        cve.__dict__.update(yaml().load(rawyaml))
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
            return True
        return False # not new

    def close(self):
        log.debug("closing cve archive at %s" % self.dbpath)
        if self._info:
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

class Media:

    id = None
    name = None
    distro = None
    timestamp = None
    hot = False

class PackagePool:

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self._conn = None
        self._medias = {}

    def _create_db(self):
        import sqlite3
        stmt = """
        CREATE TABLE pkg (
            id INTEGER PRIMARY KEY,
            name TEXT,
            evr TEXT,
            provides TEXT,
            requires TEXT,
            summary TEXT,
            media_id INTEGER
            );

        CREATE TABLE media (
            id INTEGER PRIMARY KEY,
            name TEXT,
            distro TEXT,
            timestamp INTEGER);

        CREATE INDEX pkg_name ON pkg (name);
        CREATE INDEX pkg_media_id ON pkg (media_id);
        CREATE INDEX media_match ON media (name, distro);
        """
        self._conn = sqlite3.connect(self.dbpath)
        cur = self._conn.cursor()
        cur.executescript(stmt)
        self._conn.commit()
        self._conn.close()

    def open(self):
        import sqlite3
        if not os.path.exists(self.dbpath):
            self._create_db()
        self._conn = sqlite3.connect(self.dbpath)
        log.debug("opened package database at %s", self.dbpath)
        self.open = lambda: None

    def add_media(self, name, distro):
        self.open()
        stmt = """INSERT INTO MEDIA (name, distro, timestamp)
                  VALUES (?, ?, 0)"""
        cur = self._conn.cursor()
        cur.execute(stmt, (name, distro))
        self._conn.commit()

    def _media(self, medianame, distro):
        self.open()
        mediainfo = (medianame, distro)
        try:
            media = self._medias[mediainfo]
        except KeyError:
            media = Media()
            stmt = """SELECT id, name, distro, timestamp
                      FROM media
                      WHERE name = ? and distro = ?"""
            cur = self._conn.cursor()
            try:
                if not isinstance(mediainfo[0], basestring):
                    import pdb; pdb.set_trace()
                res = cur.execute(stmt, mediainfo).next()
                (media.id, media.name, media.distro, media.timestamp) = res
            except StopIteration:
                self.add_media(medianame, distro)
                try:
                    res = cur.execute(stmt, mediainfo).next()
                    (media.id, media.name, media.distro, media.timestamp) = res
                    media.hot = True
                except StopIteration:
                    raise PackageError, "failed to insert media"
        self._medias[mediainfo] = media
        return media

    def _purge_media(self, name, distro):
        media = self._media(name, distro)
        stmt = "DELETE FROM pkg WHERE media_id = ?"
        cur = self._conn.cursor()
        cur.execute(stmt, (media.id,))
        self._medias.pop((name, distro))
        stmt = "DELETE FROM media WHERE id = ?"
        cur.execute(stmt, (media.id,))
        self._conn.commit()

    def _update_timestamp(self, medianame, distro):
        stmt = "UPDATE media SET timestamp = ? WHERE id = ?"
        media = self._media(medianame, distro)
        cur = self._conn.cursor()
        timestamp = int(math.ceil(time.time()))
        cur.execute(stmt, (timestamp, media.id))

    def pull(self, pkgiter, medianame, distro, timestamp):
        media = self._media(medianame, distro)
        if timestamp <= media.timestamp:
            return
        if not media.hot:
            self._purge_media(medianame, distro)
        for pkg in pkgiter:
            self._put(pkg, medianame, distro)
            yield True
        self._update_timestamp(medianame, distro)
        self._conn.commit()

    def _put(self, pkg, medianame, distro):
        self.open()
        cur = self._conn.cursor()
        stmt = """
            INSERT INTO pkg (
                name, evr, provides, requires, summary, media_id)
            VALUES (?, ?, ?, ?, ?, ?);
        """
        provides = "@".join(pkg.provides)
        requires = "@".join(pkg.requires)
        self._conn.text_factory = str
        media = self._media(medianame, distro)
        pars = (pkg.name, pkg.evr, provides, requires, pkg.summary,
                media.id)
        cur.execute(stmt, pars)

    def package_names(self):
        self.open()
        stmt = "SELECT DISTINCT name FROM pkg"
        cur = self._conn.cursor()
        return (name for (name,) in cur.execute(stmt))

    def find_packages(self, name_glob):
        from mdv.hdlist import Package
        self.open()
        stmt = """SELECT pkg.name, pkg.evr,
                      media.name AS media, media.distro AS distro
                  FROM pkg, media
                  WHERE
                      pkg.name GLOB ?
                      AND media.id == pkg.media_id"""
        glob = "*" + name_glob + "*"
        cur = self._conn.cursor()
        for res in cur.execute(stmt, (glob,)):
            pkg = Package()
            (pkg.name, pkg.evr,
                    medianame, distro) = res
            #pkg.provides = rawprovides.split("@")
            #pkg.requires = rawrequires.split("@")
            yield pkg, medianame, distro

    def get(self, name):
        self.open()
        raise NotImplementedError

    def close(self):
        self._conn.close()

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

    def _workdir_file(self, name_or_path, tmp=False):
        if tmp:
            return self._workdir_file(name_or_path) + ".tmp"
        return os.path.join(self.workdir(),
                self._config_path(name_or_path))

    def workdir(self):
        return self._config_path(self.config.sekt.workdir)

    def cve_database(self, tmp=False):
        return self._workdir_file(self.config.sekt.cve_database, tmp)

    def packages_database(self, tmp=False):
        return self._workdir_file(self.config.sekt.packages_database, tmp)

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
        self.packages = None
        self.tickets = None

    def open_stuff(self):
        self.cves = CVEPool(self.paths.cve_database(),
                self.paths.cve_info())
        self.packages = PackagePool(self.paths.packages_database())
        #self.tickets = TicketSource(self.cvesource,
        #        self.config.ticket_cache, self.config.bugzilla_base_url,
        #        self.config)

    def pull_cves(self, stream):
        """Pull CVE XMLs from a text stream (usually the one from
        cve.mitre.org)
        """
        from mdv.sec.pullcves import split
        cves = CVEPool(self.paths.cve_database(), self.paths.cve_info())
        for chunk in split(stream):
            new = cves.put_xml(chunk)
            yield new
        cves.close()

    def pull_packages(self):
        from mdv.hdlist import HdlistParser
        path = self.paths.packages_database()
        pool = PackagePool(path)
        def pkgiter(parser):
            while True:
                pkg = parser.next()
                if not pkg:
                    break
                yield pkg
        for media, distro in self.config.medias():
            yield "parsing", (distro, media.name)
            parser = HdlistParser(media.hdlist)
            parseriter = pkgiter(parser)
            pulliter = pool.pull(parseriter, media.name, distro, parser.timestamp)
            for _ in pulliter:
                yield "progress", parser.progress()
        pool.close()

    def correlate_cves_packages(self, cvename):
        self.open_stuff()
        names = frozenset(name.lower() for name in self.packages.package_names())
        exceptions = frozenset(["which", "file", "flood", "time", "root",
                               "check", "menu", "buffer", "dump", "listen",
                               "patch", "null", "at", "up", "connect",
                               "open"])

        def split_words(descr):
            found = []
            for rawword in cve.description.split():
                simple = "".join(ch for ch in rawword if ch.isalnum())
                found.append(simple.lower())
            return frozenset(found)
        for cve in self.cves.find_cve(cvename):
            keywords = split_words(cve.description)
            found = names.intersection(keywords) - exceptions
            if found:
                yield "F", (cve.cveid, found)
            else:
                yield "N", cve.cveid

    def find_packages(self, name):
        self.open_stuff()
        for pkg, media, distro in self.packages.find_packages(name_glob=name):
            yield pkg.name, pkg.evr, media, distro

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
        newcount = 0
        i = 0
        for i, new in enumerate(self.tasks.pull_cves(sys.stdin)):
            if new:
                newcount += 1
            if show and i % 1000 == 0:
                print i
        if show:
            print "%d parsed, %d new" % (i, newcount)

    def pull_packages(self):
        prev = 0
        show = os.isatty(1)
        for status, args in self.tasks.pull_packages():
            if show:
                if status == "progress":
                    progress = args
                    rounded = math.ceil(progress)
                    if rounded % 2.0 == 0 and rounded > prev:
                        prev = rounded
                        print ("%d%%\r" % progress),
                        sys.stdout.flush()
                        if prev >= 100:
                            prev = 0
                elif status in ("parsing", "skiping"):
                    print status, args[0], args[1]

    def correlate_cves_packages(self, options):
        for status, args in self.tasks.correlate_cves_packages(options.cve_keywords):
            if status == "F":
                print status, args[0], " ".join(args[1])

    def find_packages(self, options):
        format = "%s %s %s %s"
        if os.isatty(1):
            import commands
            _, rawcols = commands.getoutput('stty size').split()
            if rawcols:
                cols = int(rawcols)
                space = cols / 3
                format = "%%-%ds %%-%ds %%-%ds %%s" % (space, space,
                        space - 15)
        for name, version, media, distro in self.tasks.find_packages(options.pkg):
            print format % (name, version, media, distro)

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

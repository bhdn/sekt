#!/usr/bin/env python

import sys
import os
import time
import math
import logging
from cStringIO import StringIO
import ConfigParser

# external deps:

#import bugz

# yes, I hate high import times:

def bugz():
    import bugz
    return bugz

CONFIG_DEFAULTS = """\
[sekt]
workdir = ~/sekt/
cve_database = cves.sqlite
packages_database = packages.sqlite
cve_info = cves-metadata.shelve
bugzilla_base_url = https://qa.mandriva.com

[kernel_changelogs]
database = kernel-changelogs.sqlite
logs_dir = kernel-changelogs
download_command = wget --quiet -P $dest -nc '$url'
url = ftp://ftp.kernel.org/pub/linux/kernel/v2.6/ChangeLog-*

[updates]
basedir = updates

[kernel_trees]

[cves]
url = http://cve.mitre.org/data/downloads/allitems.xml.gz

[conf]
path_environment = SEKT_CONF
user_file = .sekt.conf
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

class UpdateError(Error):
    pass

class InvalidDate(UpdateError):
    pass

class UpdateNotFound(UpdateError):
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

    def kernel_trees(self):
        section = "kernel_trees"
        trees = [self._config.get(section, option) for option in
                 self._config.options("kernel_trees")]
        return trees

    def load(self, path):
        """Load the configuration file in the given path"""
        self._config.read(path)

class CVEPool:

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self._conn = None

    def open(self):
        import sqlite3
        log.info("opening cve archive at %s", self.dbpath)
        if not os.path.exists(self.dbpath):
            self._create_db()
        self._conn = sqlite3.connect(self.dbpath)
        self.open = lambda: None

    def _create_db(self):
        log.info("created database at %s", self.dbpath)
        import sqlite3
        stmt = """
            CREATE TABLE cve (
                id INTEGER PRIMARY KEY,
                cve TEXT,
                description TEXT,
                status TEXT,
                phase TEXT,
                date INTEGER,
                rawhash TEXT,
                refs TEXT);

            CREATE INDEX cve_cve ON cve (cve, rawhash);
        """
        conn = sqlite3.connect(self.dbpath)
        cur = conn.cursor()
        cur.executescript(stmt)
        conn.commit()
        conn.close()

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
            cve.date = int(node.attrib.get("date"))
        cve.description = root.find(".//desc").text
        cve.references = [{
                "source": ref.attrib.get("source"),
                "url": ref.attrib.get("url"),
                "descr": ref.text }
            for ref in root.findall(".//refs/ref")]
        # don't parse comments, as apparently we wont' need them
        return cve

    def _cve_from_db(self, cvetuples):
        names = "source", "url", "descr"
        for cvetuple in cvetuples:
            cve = CVE(None)
            (cve_id, cve.cveid, cve.description, cve.status, cve.phase,
                    cve.date, rawrefs) = cvetuple
            cve.references = []
            for line in rawrefs.split("\n"):
                if not line:
                    continue
                cols = line.split("\t")
                ref = dict(zip(names, cols))
                cve.references.append(ref)
            yield cve

    def get(self, cveid):
        self.open()
        stmtcve = """
            SELECT DISTINCT id, cve, description, status, phase, date, refs
            FROM cve
            WHERE cve = ?
        """
        cveid = self._fix_prepend(cveid)
        self._conn.text_factory = str
        cur = self._conn.cursor()
        found = cur.execute(stmtcve, (cveid,))
        try:
            cve = self._cve_from_db(found).next()
        except StopIteration:
            raise InvalidCVE
        return cve

    def get_dump(self, cveid):
        self.open()
        cve = self.get(cveid)
        return repr(cve)

    def find_cve(self, cveid, strict=False, dump=False, filter=None):
        self.open()
        templ = """
            SELECT id, cve, description, status, phase, date, refs
            FROM cve
            WHERE
        """
        cveid = self._fix_prepend(cveid)
        if not filter:
            stmteq = templ + " cve = ?"
            pars = (cveid,)
        else:
            stmteq = templ + " " + filter
            pars = ()
        self._conn.text_factory = str
        cur = self._conn.cursor()
        found = cur.execute(stmteq, pars)
        cvegen = self._cve_from_db(found)
        try:
            cve = cvegen.next()
            if dump:
                yield cve.cveid, repr(cve)
            else:
                yield cve
        except StopIteration:
            if not filter:
                idexpr = cveid + "%"
                stmtlike = templ + "cve LIKE ?"
                pars = (idexpr,)
            else:
                stmtlike = templ + " " + filter
                pars = ()
            found = cur.execute(stmtlike, pars)
            for cve in self._cve_from_db(found):
                if dump:
                    yield cve.cveid, repr(cve)
                else:
                    yield cve
        else:
            for cve in cvegen:
                if dump:
                    yield cve.cveid, repr(cve)
                else:
                    yield cve

    def _fix_prepend(self, cveid):
        if not (cveid.startswith("CVE-") or cveid.startswith("CAN-")):
            cveid = "CVE-" + cveid
        return cveid

    def _get_info(self, cveid):
        self.open()
        stmt = "SELECT DISTINCT rawhash FROM cve WHERE cve = ?"
        pars = (cveid,)
        self._conn.text_factory = str
        cur = self._conn.cursor()
        try:
            rawhash, = cur.execute(stmt, pars).next()
        except StopIteration:
            return None
        info = {"hash": rawhash}
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

    def _remove(self, cveid):
        cur = self._conn.cursor()
        stmtcve = "DELETE FROM cve WHERE cve = ?"
        cur.execute(stmtcve, (cveid,))

    def _insert(self, cve, references, rawhash):
        stmt = """
            INSERT INTO cve (cve, description, status, phase, date, refs, rawhash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        self._conn.text_factory = str
        cur = self._conn.cursor()
        references = "\n".join("\t".join((r["source"] or "",
                                          r["url"] or "", r["descr"] or ""))
                                for r in references)
        pars = (cve.cveid, cve.description, cve.status, cve.phase,
                cve.date, references, rawhash)
        cur.execute(stmt, pars)

    def put_xml(self, xml):
        self.open()
        import hashlib
        md5 = hashlib.md5()
        md5.update(xml)
        newhash = md5.hexdigest()
        cveid = self._get_id(xml)
        info = self._get_info(cveid)
        insert = False
        if info:
            if info["hash"] != newhash:
                self._remove(cveid)
                insert = True
            else:
                log.debug("no need to update %s (%s)", cveid, newhash)
        else:
            insert = True
        if insert:
            cve = self._get_cve(xml)
            log.debug("inserting %s %s", cve.cveid, newhash)
            self._insert(cve, cve.references, newhash)
            return True
        return False # not new

    def pull(self, chunkgen):
        self.open()
        for i, chunk in enumerate(chunkgen):
            if i % 1000 == 0:
                log.debug("commiting batch of CVEs")
                self._conn.commit()
            new = self.put_xml(chunk)
            yield new
        self._conn.commit()

    def close(self):
        log.debug("closing cve database at %s" % self.dbpath)
        if self._conn:
            self._conn.close()

class CVE:

    class NoDescriptionYet:
        pass

    cveid = None
    references = None
    description = None
    status = None
    phase = None
    date = None

    def __init__(self, cveid):
        self.cveid = cveid

    def __repr__(self):
        import textwrap
        description = "\n    ".join(textwrap.wrap(self.description, 75))
        if self.references:
            refs = []
            for ref in self.references:
                fields = []
                if ref["source"] and ref["source"] != ref["url"]:
                    fields.append(ref["source"])
                if ref["descr"] and ref["descr"] != ref["url"]:
                    fields.append(ref["descr"])
                if ref["url"]:
                    fields.append(ref["url"])
                if fields:
                    refs.append("ref: " + " ".join(fields))
            references = "\n".join(refs)
        else:
            references = ""
        dump = "id: %s\ndescription: %s\nstatus: %s\nphase: %s\n"\
               "%s\n" % (self.cveid, description,
                       self.status, self.phase, references)
        return dump

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

    def find_packages(self, name_glob, media=None, distro=None,
            strict=False):
        from mdv.hdlist import Package
        self.open()
        stmt = """SELECT pkg.name, pkg.evr,
                      media.name AS media, media.distro AS distro
                  FROM pkg, media
                  WHERE media.id == pkg.media_id """
        if strict:
            glob = name_glob
            stmt += " AND pkg.name == ?"
        else:
            stmt += " AND pkg.name GLOB ?"
            glob = "*" + name_glob + "*"
        params = [glob]
        if media:
            if strict:
                stmt += " AND media.name == ?"
                mediaglob = media
            else:
                stmt += " AND media.name GLOB ?"
                mediaglob = "*" + media + "*"
            params.append(mediaglob)
        if distro:
            stmt += " AND media.distro == ?"
            params.append(distro)
        cur = self._conn.cursor()
        for res in cur.execute(stmt, params):
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

class KernelTreePool:

    def __init__(self, paths):
        self.paths = paths

    def pull(self):
        for path in self.paths:
            os.system("cd %s; git pull -q" % path)

    def find_commit(self, commitid):
        import commands
        for path in self.paths:
            cmd = "cd %s; git log -n 1 --pretty=oneline %s" % (path,
                    commitid)
            status, output = commands.getstatusoutput(cmd)
            if status != 0:
                continue
            return output.strip().split(None, 1)[1]

class KernelChangelogPool:

    def __init__(self, topdir, dbpath, config, paths):
        self.topdir = topdir
        self.dbpath = dbpath
        self.config = config
        self.paths = paths
        self._conn = None
        self._versions = {}

    def open(self):
        import sqlite3
        if not os.path.exists(self.topdir):
            os.mkdir(self.topdir)
        if not os.path.exists(self.dbpath):
            self._create_db()
        self._conn = sqlite3.connect(self.dbpath)
        self._open = lambda: None

    def close(self):
        if self._conn:
            self._conn.close()

    def _create_db(self):
        import sqlite3
        stmt = """
        CREATE TABLE metadata (
            last_pull INTEGER
        );
        CREATE TABLE changelog (
            id INTEGER PRIMARY KEY,
            version TEXT
        );
        CREATE TABLE kernel_commit (
            commitid TEXT PRIMARY KEY,
            title TEXT,
            changelog_id INTEGER
        );

        CREATE INDEX changelog_version ON changelog (version);
        CREATE INDEX kernel_commit_title ON kernel_commit (title);

        INSERT INTO metadata (last_pull) VALUES (0);
        """
        self._conn = sqlite3.connect(self.dbpath)
        cur = self._conn.cursor()
        cur.executescript(stmt)
        self._conn.commit()
        self._conn.close()

    def _last_pull(self):
        stmt = "SELECT DISTINCT last_pull from metadata"
        cur = self._conn.cursor()
        try:
            last_pull, = cur.execute(stmt).next()
        except StopIteration:
            log.debug("no last changelog pull, returning 0")
            return 0
        return last_pull

    def download(self):
        from string import Template
        import subprocess
        rawtempl = self.config.kernel_changelogs.download_command
        url = self.config.kernel_changelogs.url
        dest = self.paths.kernel_changelogs_dir()
        cmd = Template(rawtempl).substitute({"dest": dest, "url": url})
        log.debug("running %s", cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        p.wait()
        if p.returncode != 0:
            output = p.stdout.read()
            raise PullError, "download failed: %s: %s" % (cmd, output)

    def _changelog_id(self, version):
        try:
            version_id = self._versions[version]
        except KeyError:
            stmt = "SELECT DISTINCT id FROM changelog WHERE version = ?"
            cur = self._conn.cursor()
            version_id, = cur.execute(stmt, (version,)).next()
            self._versions[version] = version_id
        return version_id

    def _insert_changelog(self, version):
        stmt = "INSERT INTO changelog (version) VALUES (?)"
        cur = self._conn.cursor()
        self._conn.text_factory = str
        cur.execute(stmt, (version,))

    def _insert(self, version, commit, firstline):
        stmt = """
            INSERT INTO kernel_commit (commitid, title, changelog_id)
            VALUES (?, ?, ?)"""
        cur = self._conn.cursor()
        self._conn.text_factory = str
        changelog_id = self._changelog_id(version)
        cur.execute(stmt, (commit, firstline, changelog_id))

    def _update_pull_timestamp(self):
        stmt = "UPDATE metadata SET last_pull = ?"
        last = int(math.ceil(time.time()))
        cur = self._conn.cursor()
        cur.execute(stmt, (last,))

    def put(self, version, logstream):
        self._insert_changelog(version)
        commit = None
        log = []
        first = None
        for line in logstream:
            line = line.rstrip()
            if not line:
                continue
            if not line[0].isspace():
                if first:
                    self._insert(version, commit, first)
                    log[:] = []
                    commit = None
                    first = None
                if line.startswith("commit "):
                    fields = line.split()
                    if len(fields) > 1:
                        commit = fields[1]
            else:
                if not first:
                    first = line.lstrip()
                log.append(line)
        if first:
            self._insert(version, commit, first)

    def parse(self):
        self.open()
        last = self._last_pull()
        dir = self.paths.kernel_changelogs_dir()
        for name in os.listdir(dir):
            path = os.path.join(dir, name)
            stat = os.stat(path)
            if stat.st_mtime > last:
                f = open(path)
                version = name[len("ChangeLog-"):]
                yield name, version
                self.put(version, f)
                f.close()
            self._update_pull_timestamp()
            self._conn.commit()

    def pull(self):
        self.download()
        self.parse()

    def find_commit(self, message, version=None, fuzzy=False):
        self.open()
        stmt = """
            SELECT commitid, version, title
            FROM changelog, kernel_commit
            WHERE
                kernel_commit.changelog_id = changelog.id """
        if fuzzy:
            message = "*" + message + "*"
            stmt += " AND kernel_commit.title GLOB ?"
        else:
            stmt += " AND kernel_commit.title = ?"
        parms = [message]
        if version:
            if fuzzy:
                version = "*" + version + "*"
                stmt += " AND changelog.version GLOB ?"
            else:
                stmt += " AND changelog.version = ?"
            parms.append(version)
        cur = self._conn.cursor()
        res = cur.execute(stmt, parms)
        return res

    def list_versions(self):
        self.open()
        stmt = "SELECT DISTINCT version FROM changelog"
        cur = self._conn.cursor()
        return (version for version, in cur.execute(stmt))

    def find_commits(self, version):
        self.open()
        stmt = """
            SELECT commitid, title
            FROM changelog, kernel_commit
            WHERE changelog.version = ?
                AND changelog_id = changelog.id
            """
        cur = self._conn.cursor()
        pars = (version,)
        for commit, title in cur.execute(stmt, pars):
            yield (commit.encode("utf-8"),
                    title.encode("utf-8", "replace"))

    def find_like_commits(self, commit, version):
        self.open()
        stmt = """
            SELECT ci2.commitid, ci2.title
            FROM changelog, kernel_commit AS ci1, kernel_commit AS ci2
            WHERE
                ci1.commitid = ?
                AND ci1.title = ci2.title
                AND changelog.version = ?
                AND ci2.changelog_id = changelog.id
            """
        parms = (commit, version)
        cur = self._conn.cursor()
        return cur.execute(stmt, parms)

    def get_message(self, commit):
        self.open()
        stmt = "SELECT title FROM kernel_commit WHERE commitid = ?"
        parms = (commit,)
        cur = self._conn.cursor()
        return cur.execute(stmt, parms)

class Update:

    SECTION = "update"

    _config = None

    DEFAULT = """
[update]
name =
package =
distro =
cve =
embargo =
    """

    def __init__(self, name=None):
        timestamp = time.strftime("%Y%m%d")
        if name is None:
            name = timestamp
        else:
            name = name + timestamp
        self.name = name
        self._config = ConfigParser.ConfigParser()
        self._config.readfp(StringIO(self.DEFAULT))
        self._config.set(self.SECTION, "name", self.name)

    def __repr__(self):
        sio = StringIO()
        self._config.write(sio)
        return sio.getvalue()

    def _append(self, name, value):
        cur = self._config.get(self.SECTION, name)
        values = cur.split()
        values.append(value)
        new = " ".join(values)
        self._config.set(self.SECTION, name, new)

    def bind_package(self, name):
        self._append("package", name)

    def bind_distro(self, name):
        self._append("distro", name)

    def bind_cveid(self, name):
        self._append("cve", name)

    def bind_ticket(self, name):
        self._append("ticket", name)

    def set_embargo(self, date):
        format = "%d/%m/%Y"
        try:
            emb = time.strptime(format)
        except ValueError:
            raise InvalidDate, "invalid date: %r" % date
        dump = time.strftime(format, emb)
        self._config.set(self.SECTION, "embargo", dump)

    def load(self, raw):
        self._config.readfp(StringIO(raw))

    def __getattr__(self, name):
        raw = self._config.get(self.SECTION, name)
        values = value.split()
        return values

class UpdatesTracker:

    CURRENT_NAME = "cur"

    def __init__(self, dbdir):
        self.dbdir = dbdir
        if not os.path.exists(dbdir):
            log.debug("created %s" % (dbdir))
            os.mkdir(self.dbdir)

    def _path(self, name):
        path = os.path.join(self.dbdir, name)
        return path

    def get(self, name):
        path = self._path(name)
        if not os.path.exists(path):
            raise UpdateNotFound, "update not found: %s" % (name)
        f = open(path)
        raw = f.read()
        f.close()
        update = Update()
        update.load(raw)
        return update

    def list(self, name=None):
        names = [name for name in os.listdir(self.dbdir)
                if not (name.startswith(".") or name.endswith("~")
                    or name == self.CURRENT_NAME)]
        return names

    def save(self, update):
        path = self._path(update.name)
        f = open(path, "w")
        f.write(repr(update))
        log.debug("wrote update dump at %s" % (path))
        self._reset_link(update.name)
        f.close()

    def _link_path(self):
        return os.path.join(self.dbdir, self.CURRENT_NAME)

    def _reset_link(self, name):
        path = self._path(name)
        basename = os.path.basename(path)
        link = self._link_path()
        if os.path.exists(link):
            if not os.path.islink(link):
                raise UpdateError("oops, %s was supposed to be a symlink"
                        % (link))
            log.debug("removing %s" % (link))
            os.unlink(link)
        log.debug("created link at %s pointing to %s" % (link, basename))
        os.symlink(basename, link)

    def create(self, name=None):
        update = Update(name)
        self.save(update)
        return update

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

    def kernel_changelogs_dir(self):
        return self._workdir_file(self.config.kernel_changelogs.logs_dir)

    def kernel_changelogs_database(self):
        return self._workdir_file(self.config.kernel_changelogs.database)

    def updates_dir(self):
        return self._workdir_file(self.config.updates.basedir)

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
        self.kernel_changelogs = None
        self.kernel_trees = None
        self.tickets = None

    def open_stuff(self):
        self.cves = CVEPool(self.paths.cve_database())
        self.packages = PackagePool(self.paths.packages_database())
        self.kernel_changelogs = KernelChangelogPool(self.paths.kernel_changelogs_dir(),
                                                self.paths.kernel_changelogs_database(),
                                                self.config, self.paths)
        self.kernel_trees = KernelTreePool(self.config.kernel_trees())
        self.updates = UpdatesTracker(self.paths.updates_dir())
        self.open_stuff = lambda: None

    def pull_cves(self, file=None):
        """Pull CVE XMLs from a text stream (usually the one from
        cve.mitre.org)
        """
        from mdv.sec.pullcves import split
        import subprocess
        # gzip can't handle urllib's file streams, and urllib does not
        # handle proxies easily
        cves = CVEPool(self.paths.cve_database())
        if file:
            source = open(file)
        else:
            cmd = "curl --silent '%s' | zcat" % self.config.cves.url
            log.debug("running: %s", cmd)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            source = p.stdout
        chunkgen = (chunk for chunk in split(source))
        for new in cves.pull(chunkgen):
            yield new
        if file:
            source.close()
        else:
            p.wait()
            if p.returncode != 0:
                raise PullError, "CVE pull failed: %s: %s" % (cmd,
                        p.stderr.read())
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

    def parse_kernel_changelogs(self):
        dir = self.paths.kernel_changelogs_dir()
        dbpath = self.paths.kernel_changelogs_database()
        pool = KernelChangelogPool(dir, dbpath, self.config, self.paths)
        for name in pool.parse():
            yield name
        pool.close()

    def pull_kernel_trees(self):
        self.open_stuff()
        self.kernel_trees.pull()

    def pull(self):
       yield "pulling cves"
       all(self.pull_cves())
       yield "pulling packages"
       all(self.pull_packages())
       yield "fetching kernel changelogs"
       self.fetch_kernel_changelogs()
       yield "parsing kernel changelogs"
       all(self.parse_kernel_changelogs())
       yield "pulling kernel trees"
       self.pull_kernel_trees()
       yield "wow! it is done"

    def correlate_cves_packages(self, cvename, strict=False):
        self.open_stuff()
        names = frozenset(name.lower() for name in self.packages.package_names())
        exceptions = frozenset(["which", "file", "flood", "time", "root",
                               "check", "menu", "buffer", "dump", "listen",
                               "patch", "null", "at", "up", "connect",
                               "open"])
        extra = frozenset(["kernel"])
        keywords = names.union(extra)
        def split_words(descr):
            found = []
            for rawword in cve.description.split():
                simple = "".join(ch for ch in rawword if ch.isalnum())
                found.append(simple.lower())
            return frozenset(found)
        for cve in self.cves.find_cve(cvename, strict=strict):
            words = split_words(cve.description)
            found = keywords.intersection(words) - exceptions
            if found:
                yield "F", (cve.cveid, found)
            else:
                yield "N", cve.cveid

    def cve_for_advisory(self, cveid):
        self.open_stuff()
        for cve in self.cves.find_cve(cveid, strict=True):
            desc = "%s (%s)" % (cve.description, cve.cveid)
            yield desc

    def find_packages(self, name, media=None, distro=None, strict=False):
        self.open_stuff()
        gen = self.packages.find_packages(name_glob=name, media=media,
                distro=distro, strict=strict)
        for pkg, media, distro in gen:
            yield pkg.name, pkg.evr, media, distro

    def find_kernel_commit(self, message, fuzzy=False):
        self.open_stuff()
        return self.kernel_changelogs.find_commit(message, fuzzy=fuzzy)

    def fetch_kernel_changelogs(self):
        self.open_stuff()
        self.kernel_changelogs.download()

    def list_kernel_releases(self):
        self.open_stuff()
        return self.kernel_changelogs.list_versions()

    def list_kernel_commits(self, version):
        self.open_stuff()
        return self.kernel_changelogs.find_commits(version)

    def get_kernel_commit(self, commit):
        self.open_stuff()
        return self.kernel_changelogs.get_message(commit)

    def find_kernel_cves(self, version):
        # tries to find all CVEs that have references to commits from this
        # release
        import re
        expr = re.compile("git\.kernel\.org/(?:.*h=|linus/)(?P<ci>[0-9a-f]+)")
        cveexpr = re.compile("(?P<cve>CVE-\d{4}-\d{4})")
        self.open_stuff()
        # FIXME just search by CVEs using the database
        cis = self.kernel_changelogs.find_commits(version)
        allcommits = dict(cis)
        ids = allcommits.keys()
        cvecommits = set()
        yield "status", "looking for explicit CVE references in commit titles"
        for ci, message in allcommits.iteritems():
            found = cveexpr.search(message)
            if found:
                cveid = found.group("cve")
                yield "found", (ci, cveid, message)
        yield "status", "looking for direct references to commits in CVE references"
        gitfilter = "refs LIKE '%git.kernel.org%'"
        for cve in self.cves.find_cve("", filter=gitfilter):
            match = [id for id in ids if
                    any((id in ref["url"]) for ref in cve.references)]
            if match:
                for cimatch in match:
                    yield "found", (cimatch, cve.cveid, allcommits[cimatch])
            for ref in cve.references:
                for found in expr.finditer(ref["url"]):
                    foundci = found.group("ci")
                    cvecommits.add((cve.cveid, foundci))
        yield "status", "looking for CVE commits with same title in the version %s" % version
        foundcves = set()
        for cveid, ci in cvecommits:
            for ci2, title in self.kernel_changelogs.find_like_commits(ci,
                    version):
                yield "found", (ci2, cveid, title)
                foundcves.add((cveid, ci))
        cvecommits.difference_update(foundcves)
        cvemessages = set()
        for cveid, ci in cvecommits:
            message = self.kernel_trees.find_commit(ci)
            if message:
                cvemessages.add((cveid, ci, message))
        for cveid, ci, message in cvemessages:
            finditer = self.kernel_changelogs.find_commit(message, version=version)
            for ci2, _version, _message in finditer:
                yield "found", (ci2, cveid, message)

    def create_update(self, name=None, packages=None, distros=None,
            cves=None, embargo=None):
        """
        Create a new update in the (local) updates tracker

        @name: the task name, optional
        @packages: list of packages (SRPM) to be bound with the
                   update
        @distros: list of distros
        @cves: list of CVE IDs
        @embargo: a struct_time object or unix time with the embargo limit
        date.
        """
        self.open_stuff()
        update = self.updates.create(name)
        if packages:
            for package in packages:
                update.bind_package(package)
        if distros:
            for distro in distros:
                update.bind_distro(distro)
        if cves:
            for cveid in cves:
                update.bind_cveid(cveid)
        if embargo:
            update.set_embargo(embargo)
        self.updates.save(update)

    def show_update(self, name):
        self.open_stuff()
        update = self.updates.get(name)
        return repr(update)

    def list_updates(self):
        self.open_stuff()
        return self.updates.list()

    def init(self):
        path = self.paths.workdir()
        if os.path.exists(path):
            return False
        log.info("created %s", path)
        os.mkdir(path)
        return True

    def dump_cve(self, cveid, strict=False):
        self.open_stuff()
        dump = self.cves.get_dump(cveid)
        return dump

    def find_cve(self, cveid, strict=False, dump=False):
        self.open_stuff()
        return self.cves.find_cve(cveid, strict=strict, dump=dump)

    def finish(self):
        if self.cves:
            self.cves.close()
        if self.tickets:
            self.tickets.close()

class Interface:
    def __init__(self, config, tasks):
        self.config = config
        self.tasks = tasks

    def pull_cves(self, options):
        show = os.isatty(1)
        newcount = 0
        i = 0
        for i, new in enumerate(self.tasks.pull_cves(options.file)):
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

    def pull_kernel_trees(self):
        self.tasks.pull_kernel_trees()

    def parse_kernel_changelogs(self):
        for name in self.tasks.parse_kernel_changelogs():
            print name

    def pull(self):
        for status in self.tasks.pull():
            print status

    def correlate_cves_packages(self, options):
        cvegen = self.tasks.correlate_cves_packages(options.cve_keywords,
                strict=options.strict)
        for status, args in cvegen:
            if status == "F":
                print status, args[0], " ".join(args[1])

    def cve_for_advisory(self, options):
        cve = options.cve_for_advisory
        for descr in self.tasks.cve_for_advisory(cve):
            print descr
            print

    def find_packages(self, options):
        format = "%s\t%s\t%s\t%s"
        if os.isatty(1):
            import commands
            _, rawcols = commands.getoutput('stty size').split()
            if rawcols:
                cols = int(rawcols)
                space = cols / 3
                format = "%%-%ds %%-%ds %%-%ds %%s" % (space, space,
                        space - 15)
        gen = self.tasks.find_packages(options.pkg, media=options.media,
                distro=options.distro, strict=options.strict)
        for name, version, media, distro in gen:
            print format % (name, version, media, distro)

    def find_kernel_commit(self, options):
        findgen = self.tasks.find_kernel_commit(options.kci,
                fuzzy=options.fuzzy)
        for commit, version, message in findgen:
            print commit, version, message

    def fetch_kernel_changelogs(self):
        self.tasks.fetch_kernel_changelogs()

    def list_kernel_releases(self):
        for release in self.tasks.list_kernel_releases():
            print release

    def list_kernel_commits(self, options):
        for commit, title in self.tasks.list_kernel_commits(options.kcommits):
            print commit[:7], title

    def find_kernel_cves(self, options):
        for type, extra in self.tasks.find_kernel_cves(options.kcve):
            if type == "status":
                print "*", extra
            else:
                ci, cveid, message = extra
                print cveid, ci[:8], message

    def get_kernel_commit(self, options):
        for message in self.tasks.get_kernel_commit(options.kcommit):
            print options.kcommit[:8], message

    def create_update(self, options):
        self.tasks.create_update(options.mkupd,
                packages=options.with_pkg, distros=options.with_distro,
                cves=options.with_cve, embargo=options.embargo)

    def show_update(self, options):
        print self.tasks.show_update(options.upd)

    def list_updates(self):
        for name in self.tasks.list_updates():
            print name

    def init(self):
        if self.tasks.init():
            print "done"
        else:
            print "already initialized"

    def dump_conf(self):
        print repr(self.config)

    def dump_cve(self, options):
        try:
            found = self.tasks.find_cve(options.cve,
                    strict=options.strict, dump=True)
            if os.isatty(1) and not os.getenv("SEKT_NOPIPE"):
                import subprocess
                p = subprocess.Popen(["less"], stdin=subprocess.PIPE)
                try:
                    for cveid, dump in found:
                        p.stdin.write(dump)
                        p.stdin.write("\n")
                finally:
                    p.stdin.close()
                    p.wait()
            else:
                sys.stdout.writelines(rawcve for cveid, rawcve in found)
        except IOError, e:
            if e.errno != 32: # broken pipe
                raise

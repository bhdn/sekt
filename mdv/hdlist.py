import sys
import os
import gzip

#import rpmver

class TypeSynthesis: pass
class TypeHdlist: pass

class Package:
    
    def __init__(self):
        self.name = None
        self.evr = None
        self.provides = None
        self.requires = None
        self.summary = None

class HdlistParser:

    def __init__(self, path):
        self.path = path
        self.compressed = False
        self._parsed = {}
        self._file = None
        self._done = False
        self.timestamp = None
        self.guess_type()
        self.get_info()

    def get_info(self):
        stat = os.stat(self.path)
        self._size = stat.st_size
        self.timestamp = stat.st_mtime

    def guess_type(self):
        name = os.path.basename(self.path)
        if name.startswith("synthesis."):
            self.type = TypeSynthesis
        if name.endswith(".cz"):
            self.compressed = True

    def get(self, name):
        try:
            return self._parsed[name]
        except KeyError:
            while True:
                pkg = self.next()
                if not pkg:
                    break
                if pkg.name in self._parsed:
                    raise "opa:", pkg.name
                self._parsed[pkg.name] = pkg
                if pkg.name == name:
                    return pkg

    def next(self):
        if self._file is None:
            if self.compressed:
                self._file = gzip.GzipFile(self.path, "r")
            else:
                self._file = open(self.path)
        stop = False
        info = {}
        for line in self._file:
            line = line.strip()
            if not line:
                continue
            if line.startswith("@info@"):
                # pkg done
                stop = True
            fields = line.split("@")
            name = fields[1]
            args = fields[2:]
            info[name] = args
            if stop:
                break
        else:
            self._done = True
            if not info:
                return
        if self.compressed:
            readed = self._file.myfileobj.tell()
        else:
            readed = self._file.tell()
        self._progress = (100.0 / self._size) * readed
        pkg = Package()
        namever = info["info"][0]
        nevr = namever.rsplit("-", 2)
        pkg.name = nevr[0]
        pkg.evr = "-".join(nevr[1:])
        pkg.summary = info["summary"][0]
        pkg.provides = info.get("provides", [])
        pkg.requires = info.get("requires", [])
        pkg.inforest = "@".join(info["info"][1:])
        return pkg

    def progress(self):
        return self._progress

class MediaInfo:

    hdlist = None
    name = None
    rpms = None
    noauto = False
    xmlinfo = None
    size = None

import sys
import os
import re
import bsddb
from cStringIO import StringIO

namere = re.compile("name=\"(?P<name>CVE-....-....)\"")

def get_id(line):
    found = namere.search(line)
    if found:
        return found.group("name")

def split(input, path):
    body = StringIO() # will be discarded
    f = body
    cveid = None
    db = bsddb.btopen(path, "w")
    count = 0
    for line in input:
        if line.startswith("<item"):
            cveid = get_id(line)
            f = StringIO()
            f.write(line)
        elif line.startswith("</item"):
            f.write(line)
            db[cveid] = f.getvalue()
            count += 1
            f = body
        else:
            f.write(line)
    db.sync()
    db.close()

if __name__ == "__main__":
    split(open(sys.argv[1]), sys.argv[2:2] or "./cves.bsddb")

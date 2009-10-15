import sys
import os
from cStringIO import StringIO

def get_id(line):
    found = namere.search(line)
    if found:
        return found.group("name")

def split(input):
    body = StringIO() # will be discarded
    f = body
    for line in input:
        if line.startswith("<item"):
            f = StringIO()
            f.write(line)
        elif line.startswith("</item"):
            f.write(line)
            yield f.getvalue()
            f = body
        else:
            f.write(line)

if __name__ == "__main__":
    split(open(sys.argv[1]), sys.argv[2:2] or "./cves.bsddb")

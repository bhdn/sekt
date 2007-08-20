#!/usr/bin/python

import sys
import os
import optparse
import shelve

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


class SecurityTicket(Ticket):

    _ticket = None
    cve = None
    sources = None
    url = None
    valid = None
    release_status = None

    def __init__(self, *args, **kwargs):
        Ticket.__init__(self, *args, **kwargs)
        self._parse_ticket()

    def _parse_ticket(self):
        pass

    def __getattr__(self, name):
        return getattr(self._ticket, name)


class TicketSource:

    def __init__(self, config):
        self.config = config

    def search(self):
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

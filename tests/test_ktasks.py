import os
import shutil
import unittest

from mdv.kernel import ktasks

class TestKtasks(unittest.TestCase):

    workdir = "tests/data/"
    cachefile = os.path.join(workdir, "ticket-cache.shelf")
    cve_archive = "/home/bogdano/teste/kernel/CVEs/database/tree.zip"

    def _get_cve_source(self):
        return ktasks.CVESource(self.cve_archive)

    def _get_ticket_source(self, cvesource):
        return ktasks.TicketSource(cvesource, self.cachefile)

    def test_cve_source(self):
        source = ktasks.CVESource(self.cve_archive)
        cveid = "CVE-2000-1044"
        cve = source.get(cveid)
        self.assertEqual(cve.cveid, cveid)
        self.assertEqual(cve.status, "Entry")
        self.assertEqual(cve.phase, None) # this specific entry has no phase
        self.assertEqual(cve.references, 
            [{"source": "SUSE", 
              "url": "http://archives.neohapsis.com/archives/linux/suse/2000-q4/0262.html",
              "descr": "SuSE-SA:2000:042"},
             {"source": "BID",
                 "url": "http://www.securityfocus.com/bid/1820",
              "descr": "1820"},
             {"source": "XF",
              "url": "http://xforce.iss.net/static/5394.php",
              "descr": "ypbind-printf-format-string"}])

    def test_ticket_source(self):
        cvesource = self._get_cve_source()
        source = self._get_ticket_source(cvesource)
        ticket = source.get("32160")
        self.assertEqual(ticket.title, u"Erro na instala\xc3\xa7\xc3\xa3o"\
                " do mandriva cs4 na placa ASUS P5VD2-X")
        self.assertEqual(ticket.assignee, "bogdano@mandriva.com.br")
        self.assertEqual(ticket.cc, ["anne.nicolas@mandriva.com"])
        self.assertEqual(ticket.product, "Mandriva Corporate Server")

    def test_security_ticket(self):
        #TODO move to setUp
        cvesource = self._get_cve_source()
        ticketsource = self._get_ticket_source(cvesource)
        ticket = ticketsource.get("27958")
        secticket = ktasks.SecurityTicket(ticket, cvesource)
        self.assertEqual(secticket.title, ticket.title)
        self.assertEqual(secticket.assignee, ticket.assignee)
        self.assertEqual(secticket.cc, ticket.cc)
        self.assertEqual(secticket.product, ticket.product)
        self.assertEqual(secticket.comments, ticket.comments)
        self.assertEqual(secticket.attachments, ticket.attachments)
        #
        self.assertEqual(secticket.title, 
                "SECURITY ADVISORY: CVE-2006-5753")
        self.assertEqual(secticket.cveid, "CVE-2006-5753")
        self.assertEqual(secticket.release_status, 
                [{"CS3.0": "NEW", "2006.0": "NEW", "2007.0": "NEW"},
                 {"CS3.0": "NEW", "2006.0": "NEW", "2007.0": "FIXED"},
                 {"CS3.0": "NEW", "2006.0": "NEW", "2007.0": "RELEASED"},
                 {"CS3.0": "NEW", "2006.0": "OPEN", "2007.0": "RELEASED"},
                 {"CS3.0": "NEW", "2006.0": "FIXED", "2007.0": "RELEASED"},
                 {"CS3.0": "NEW", "2006.0": "RELEASED", "2007.0":
                     "RELEASED"}])
        self.assertEqual(secticket.cve.description, 
                "Unspecified vulnerability in the listxattr system call "\
                "in Linux kernel, when a \"bad inode\" is present, allows "\
                "local users to cause a denial of service (data "\
                "corruption) and possibly gain privileges via "\
                "unknown vectors.")

    def test_ticket_source_security_tickets(self):
        from itertools import islice
        cvesource = self._get_cve_source()
        ticketsource = self._get_ticket_source(cvesource)
        items = list(islice(ticketsource.security_tickets(), 3))
        self.assertEqual(items[0].cveid, items[0].cve.cveid)
        self.assertEqual(items[1].cveid, items[1].cve.cveid)
        self.assertEqual(items[2].cveid, items[2].cve.cveid)

    def test_ticket_cache(self):
        from itertools import islice
        cvesource = self._get_cve_source()
        ticketsource = self._get_ticket_source(cvesource)
        query = "SECURITY ADVISORY"
        items = list(islice(ticketsource.search(query), 3))
        items2 = list(islice(ticketsource.search(query), 3))
        # ensure the in-memory cache is returning the always the same
        # objects (not copies)
        self.assertTrue(items[0] is items2[0])
        self.assertTrue(items[1] is items2[1])
        self.assertTrue(items[2] is items2[2])
        ticketsource._cache.close()
        ticketsource._cache.load()
        items3 = list(islice(ticketsource.search(query), 3))
        self.assertEqual(items[0].title, items3[0].title)
        self.assertEqual(items[0].comments, items3[0].comments)
        self.assertEqual(items[1].title, items3[1].title)
        self.assertEqual(items[1].comments, items3[1].comments)
        self.assertEqual(items[2].title, items3[2].title)
        self.assertEqual(items[2].comments, items3[2].comments)

    def setUp(self):
        if not os.path.exists(self.workdir):
            os.makedirs(self.workdir)

    def tearDown(self):
        if os.path.exists(self.cachefile):
            shutil.rmtree(cachefile)

if __name__ == "__main__":
    unittest.main()

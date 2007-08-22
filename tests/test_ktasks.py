import unittest

from mdv.kernel import ktasks

class TestKtasks(unittest.TestCase):

    cve_archive = "/home/bogdano/teste/kernel/CVEs/database/tree.zip"

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
        cvesource = ktasks.CVESource(self.cve_archive)
        source = ktasks.TicketSource(cvesource)
        ticket = source.get("32160")

    def setUp(self):
        pass

    def tearDown(self):
        pass

if __name__ == "__main__":
    unittest.main()

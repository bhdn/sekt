import os
import shutil
import unittest

from mdv.kernel import ktasks

class KTasksTest(unittest.TestCase):

    workdir = "tests/data/"

    def setUp(self):
        if not os.path.exists(self.workdir):
            os.makedirs(self.workdir)

    def tearDown(self):
        if os.path.exists(self.workdir):
            shutil.rmtree(self.workdir)


class TestKtasks(KTasksTest):

    cachefile = os.path.join(KTasksTest.workdir, "ticket-cache.shelf")
    cve_archive = "/home/bogdano/teste/kernel/CVEs/database/tree.zip"
    bugzilla_base_url = "https://qa.mandriva.com"

    def _get_cve_source(self):
        return ktasks.CVESource(self.cve_archive)

    def _get_ticket_source(self, cvesource):
        config = ktasks.Config()
        return ktasks.TicketSource(cvesource, self.cachefile,
                self.bugzilla_base_url, config)

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
        # check release status matching
        config = ktasks.Config(defaults={"cve": {"valid_status": ["FOO",
            "BAR", "BAZ"]}})
        comments = [
            {"who": "me", "when": "never", "what": """
This is a simple note on top of the status bar.

2006.0: FOO | 2007.0: FOO | 2008.0: BAR"""},
            {"who": "me", "when": "tomorrow", "what": """\
FOO: bli | bla: ZZZ
"""}]
        release_status = ktasks.SecurityTicket._find_release_status(config,
                comments)
        self.assertTrue(release_status, [{"2006.0": "FOO", "2007.0": "FOO",
            "2008.0": "BAR"}])
        # check ticket wrapping
        ticket = ticketsource.get("27958")
        secticket = ktasks.SecurityTicket(ticket, cvesource,
                ktasks.Config())
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


class TestConfig(KTasksTest):

    defaults = """\
foo: bar
bar: baz
baz: bleh
bli:
    - bla
    - blou
    - zha!
yat:
    yot:
        - yut
        - bla
        - bli
    you:
        - kkk
        - kekeke
        - kikiki
"""

    def test_cli_option(self):
        config = ktasks.Config(defaults={})
        config.parse(self.defaults)
        args = ["-o", "xi=xar", "-o", "iut=iar", "-o", "yet=yot=yat",
                "-o", "yat.yar=heia!"]
        options, args = ktasks.parse_options(args)
        config.merge(options.config_options)
        self.assertEqual(config.xi, "xar")
        self.assertEqual(config.iut, "iar")
        self.assertEqual(config.yet, "yot=yat")
        self.assertEqual(config.yat.yar, "heia!")

    def _check_defaults(self, config):
        self.assertEqual(config.foo, "bar")
        self.assertEqual(config["foo"], "bar")
        self.assertEqual(config.bar, "baz")
        self.assertEqual(config.baz, "bleh")
        self.assertEqual(config.bli, ["bla", "blou", "zha!"])
        self.assertEqual(config["bli"], ["bla", "blou", "zha!"])
        self.assertTrue(isinstance(config.yat, ktasks.ConfWrapper))
        self.assertEqual(config.yat.yot, ["yut", "bla", "bli"])
        self.assertEqual(config.yat.you, ["kkk", "kekeke", "kikiki"])
        self.assertEqual(config["yat"],
                {"yot": ["yut", "bla", "bli"],
                 "you": ["kkk", "kekeke", "kikiki"]})

    def test_parsing_yaml(self):
        config = ktasks.Config(defaults={})
        config.parse(self.defaults)
        self._check_defaults(config)

    def test_parsing_file(self):
        path = os.path.join(self.workdir, "sample.conf")
        f = open(path, "w+")
        f.write(self.defaults)
        f.close()
        config = ktasks.Config(defaults={})
        config.load(path)
        self._check_defaults(config)

    def test_honor_raw_defaults(self):
        class NewConfig(ktasks.Config):
            raw_defaults = """\
um: dois
tres: quatro
cinco: seis
sete: oito
isso:
    - aquilo
    - outra
nada:
    nadar:
        - nadador
        - nadando
    vazio:
        - esvaziar
        - vazar
"""
        config = NewConfig()
        self.assertEqual(config.um, "dois")
        self.assertEqual(config.tres, "quatro")
        self.assertEqual(config.cinco, "seis")
        self.assertEqual(config.sete, "oito")
        self.assertEqual(config.isso, ["aquilo", "outra"])
        self.assertEqual(config.nada.nadar, ["nadador", "nadando"])
        self.assertEqual(config.nada.vazio, ["esvaziar", "vazar"])

    def test_mergeconf(self):
        base = {"one": "two", 
                "three": ["3.1", "3.2", "3.3"],
                "four": {"item": "value", "foo": "bar"},
                "misc": 1}
        other = {"bla": "bleh",
                 "three": ["3.4!"],
                 "four": {"new": "item"},
                 "misc": 3}
        new = ktasks.mergeconf(base, other)
        self.assertEqual(new["one"], "two")
        self.assertEqual(new["three"], ["3.1", "3.2", "3.3", "3.4!"])
        self.assertEqual(new["four"], {"item": "value", "foo": "bar",
            "new": "item"})
        self.assertEqual(new["misc"], 3)
        self.assertEqual(new["bla"], "bleh")


if __name__ == "__main__":
    unittest.main()

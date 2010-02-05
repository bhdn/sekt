import sys
import os
import optparse

from mdv.sec.tasks import Config, SecteamTasks, Error

class DontGetInTheWayFormatter(optparse.IndentedHelpFormatter):
    """Class only intended to go around the crappy text wrapper"""

    def format_description(self, description):
        return description

class SektCommand(object):

    descr = "The base sekt command."
    usage = "[options] [args]"

    def create_parser(self):
        parser = optparse.OptionParser(formatter=DontGetInTheWayFormatter())
        return parser

    def init_parser(self, parser):
        def parse_option(option, opt_str, value, parser, *args, **kwargs):
            kv = value.split("=", 1)
            if len(kv) != 2:
               raise optparse.OptionValueError, "-o accepts values only in "\
                       "the name=value form"
            levels = kv[0].split(".")
            lastv = kv[1]
            for name in levels[:0:-1]:
                lastv = {name: lastv}
            parser.values.config_options[levels[0]] = lastv
        parser.set_usage(self.usage)
        parser.set_description(self.descr)
        parser.set_defaults(config_options={})
        parser.add_option("-v", "--verbose", action="store_true", default=False)
        parser.add_option("-o", "--option", type="string", action="callback",
                callback=parse_option,
                help="set one configuration option in the form opt=val")

    def create_config(self):
        config = Config()
        return config

    def update_config(self, config, opts, args):
        config.merge(opts.config_options)
        path = (os.environ.get(config.conf.path_environment) or
                os.path.expanduser(os.path.join("~", config.conf.user_file)))
        if os.path.exists(path):
            config.load(path)

    def setup_logging(self, config, opts, args):
        if opts.verbose:
            import logging
            logging.basicConfig(level=logging.DEBUG)

    def run(self, tasks):
        print "Done."

    def main(self):
        try:
            parser = self.create_parser()
            config = self.create_config()
            self.init_parser(parser)
            opts, args = parser.parse_args(sys.argv[1:])
            self.update_config(config, opts, args)
            self.setup_logging(config, opts, args)
            tasks = SecteamTasks(config)
            self.config = config
            self.opts = opts
            self.args = args
            self.tasks = tasks
            self.run()
        except Error, e:
            sys.stderr.write("error: %s\n" % (e))
        except KeyboardInterrupt:
            sys.stderr.write("interrupted\n")

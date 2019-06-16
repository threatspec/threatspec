import logging
logger = logging.getLogger(__name__)

import click, sys
from threatspec import app

def validate_logging(ctx, param, value):
    levels = {
        "none": 100,
        "crit": logging.CRITICAL,
        "error": logging.ERROR,
        "warn": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG
    }
    if value.lower() in levels:
        return levels[value.lower()]
    raise click.BadParameter("Log level must be one of: {}".format(", ".join(levels.keys())))

def configure_logger(level, verbose):
    if verbose:
        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=level)
    else:
        logging.basicConfig(format='%(message)s', level=level)        

@click.group()
@click.option("--log-level", "-l", callback=validate_logging, default="info", help="Set the log level. Must be one of: crit, error, warn, info, debug, none.")
@click.option("--verbose/--no-verbose", default=False, help="Makes logging more verbose.")
@click.version_option()
def cli(log_level, verbose):
    configure_logger(log_level, verbose)
    
@cli.command()
def init():
    threatspec = app.ThreatSpecApp()
    threatspec.init()

@cli.command()
def run():
    threatspec = app.ThreatSpecApp()
    threatspec.run()

@cli.command()
def report():
    threatspec = app.ThreatSpecApp()
    threatspec.report()
    
if __name__ == '__main__':
    cli(None, None)

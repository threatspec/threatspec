import logging
logger = logging.getLogger(__name__)

import click
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
    """
    threatspec - threat modeling as code

    threatspec is an open source project that aims to close the gap between
    development and security by bringing the threat modelling process further
    into the development process. This is achieved by having developers and
    security engineers write threat specifications alongside code, then
    dynamically generating reports and data-flow diagrams from the code. This
    allows engineers to capture the security context of the code they write,
    as they write it.
    
    Usage:
    
    # Initialise threatspec in the current directory
    $ threatspec init
    
    # Configure the source code paths
    $ $EDITOR threatspec.yaml
    
    # Run threatspec against the source code paths
    $ threatspec run
    
    # Generate the threat mode report
    $ threatspec report
    
    For more information for each subcommand use --help. For everything else,
    visit the website at https://threatspec.org
    """

    configure_logger(log_level, verbose)
    
    
@cli.command()
def init():
    """
    Initialise threatspec in the current directory.

    This will create a project configuration file called threatspec.yaml. Edit
    this file to configure the project name and description as well the source
    code paths for threatspec to scan.

    This command will also create the threatmodel directory in the current
    path. This directory contains the json output files from threatspec run.

    The following file contains the collection of mitigations, acceptances,
    connections etc identified as annotations in code:

        threatmodel/threatmodel.json

    The following three threat model library files are loaded each time threatspec
    is run. If new threats, controls or components are found, they are added to these
    files.
    
    This allows threats, controls and components to be used across projects
    and allows you to create threat library files, for example from OWASP or CWE
    data. When threatspec loads paths configured in threatspec.yaml, it checks
    each path to see if a threatspec.yaml file exists. If so, it attempts to load the
    below files.

    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json
    """

    threatspec = app.ThreatSpecApp()
    threatspec.init()


@cli.command()
def run():
    """
    Run threatspec against source code files.

    This command loads the configuration file and for each configured path it first
    checks to see if a threatspec.yaml file exists in the path. If it does, it loads
    the three library json files.

    Once all the library files have been loaded from the paths, threatspec run will
    recursively parse each file in the path, looking for threatspec annotations.
    
    You can exclude patterns from being searched (for example 'node_modules') using the
    'ignore' key for the paths in the configuration file. See the documentation for
    more information.

    After all the source files have parsed, threatspec run will generate the
    threatmodel/threatmodel.json file as well as the three library files:

    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json
    """

    threatspec = app.ThreatSpecApp()
    threatspec.run()


@cli.command()
@click.option("--output", "-o", default="markdown", help="Report output format. Available values: text, json, template, markdown (default).")
@click.option("--file", "-f", help="Output filename name. The default is set by the report mode.")
@click.option("--template", "-t", help="Template file to load if '--output template' selected.")
def report(output, file, template):
    """
    Generate the threatspec threat model report.

    This will by default use Graphviz to generate a visualisation of the threat model,
    and embed it in a threat model markdown document in the current directory:
    
    ThreatModel.md

    This document contains tables of mitigations etc (including any tests), as
    well as connections and reviews.
    """

    threatspec = app.ThreatSpecApp()
    threatspec.report(output, file, template)
    

if __name__ == '__main__':
    cli(None, None)

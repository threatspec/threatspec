import logging
logger = logging.getLogger(__name__)

import os
import sys
import uuid
import magic
from threatspec import config, data, parser, reporter, threatmodel


class ThreatSpecApp():

    def __init__(self):
        self.threat_library = threatmodel.ThreatLibrary()
        self.control_library = threatmodel.ControlLibrary()
        self.component_library = threatmodel.ComponentLibrary()

        self.threatmodel = threatmodel.ThreatModel()
        self.threatmodel.threat_library = self.threat_library
        self.threatmodel.control_library = self.control_library
        self.threatmodel.component_library = self.component_library

        self.threatmodel.run_id = uuid.uuid4().hex
        logger.debug("Setting run id to {}".format(self.threatmodel.run_id))

        self.config = config.Config()
        self.parser = None
        self.reporter = None

        self.loaded_source_paths = {}
        self.loaded_library_paths = {}

    def get_parser_for_path(self, path, config_path):
        if config_path.mime:
            mime = config_path.mime
        else:
            mime = magic.from_file(path, mime=True)
        _, ext = os.path.splitext(path)
        
        if mime == "text/plain":
            if ext in [".yaml", ".yml"]:
                return parser.YamlFileParser(self.threatmodel)
            elif ext in [".json"]:
                return parser.YamlFileParser(self.threatmodel)
            elif ext in [".txt"]:
                return parser.TextFileParser(self.threatmodel)
            else:
                logger.warn("Unsupported file extension {} for mime type text/plain for file {}".format(ext, path))
                return None
        else:
            return parser.SourceFileParser(self.threatmodel, mime)

    def parse_source(self, paths, parent):
        for config_path in paths:
            abs_path = data.abs_path(parent, config_path.path)
            
            if data.blacklisted_path(abs_path):
                logger.debug("Skipping path {} as it is blacklisted".format(abs_path))
                continue
            
            logger.debug("Processing source path {}".format(abs_path))
            if abs_path in self.loaded_source_paths:
                logger.debug("Skipping source path {} as it has already been processed".format(abs_path))
                continue
            
            self.loaded_source_paths[abs_path] = True  # We've seen it now
            if data.is_threatspec_path(abs_path):
                logger.debug("Found threatspec.yaml, loading source configuration from {}".format(abs_path))
                new_config = config.Config()

                new_config_file = data.abs_path(abs_path, "threatspec.yaml")
                (valid, error) = data.validate_yaml_file(new_config_file, os.path.join("data", "config_schema.json"))
                if not valid:
                    logger.error("Couldn't validate the configation file {}: {}".format(abs_path, error))
                    sys.exit(1)

                new_config.load(data.read_yaml(new_config_file))
                self.parse_source(new_config.paths, abs_path)

            for path in data.recurse_path(abs_path):
                if data.path_ignored(path, config_path.ignore):
                    logger.debug("Skipping ignored file path: {}".format(path))
                    continue
                logger.debug("Parsing source files in path {}".format(path))
                if os.path.isfile(path):
                    self.parser = self.get_parser_for_path(path, config_path)
                    if self.parser:
                        self.parser.parse_file(path)

    def load_threat_model(self, path):
        filename = data.abs_path(path, "threatmodel", "threatmodel.json")

        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "threatmodel_schema.json"))
        if not valid:
            logger.error("Couldn't validate the threat model file {}: {}".format(filename, error))
            sys.exit(1)

        try:
            self.threatmodel.load(data.read_json(filename))
            logger.debug("Loaded threat model from {}".format(filename))
        except FileNotFoundError:
            pass

    def save_threat_model(self):
        data.write_json_pretty(self.threatmodel.save(), data.cwd(), "threatmodel", "threatmodel.json")  # TODO: Unhardcode

    def load_threat_models(self):
        self.load_threat_model(data.cwd())
        
        for import_path in self.config.imports:
            abs_import_path = data.abs_path(import_path.path)
            if abs_import_path == data.cwd():
                continue  # Local path processed above
            self.load_threat_model(abs_import_path)
        
    def load_threat_library(self, path, local=False):
        filename = data.abs_path(path, "threatmodel", "threats.json")

        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "threats_schema.json"))
        if not valid:
            logger.error("Couldn't validate the threat library file {}: {}".format(filename, error))
            sys.exit(1)

        try:
            if local:
                run_id = self.threatmodel.run_id
            else:
                run_id = None
            self.threat_library.load(data.read_json(filename), run_id)
            logger.debug("Loaded threat library from {}".format(filename))
        except FileNotFoundError:
            pass

    def load_control_library(self, path, local=False):
        filename = data.abs_path(path, "threatmodel", "controls.json")

        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "controls_schema.json"))
        if not valid:
            logger.error("Couldn't validate the control library file {}: {}".format(filename, error))
            sys.exit(1)

        try:
            if local:
                run_id = self.threatmodel.run_id
            else:
                run_id = None
            self.control_library.load(data.read_json(filename), run_id)
            logger.debug("Loaded control library from path {}".format(filename))
        except FileNotFoundError:
            pass

    def load_component_library(self, path, local=False):
        filename = data.abs_path(path, "threatmodel", "components.json")

        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "components_schema.json"))
        if not valid:
            logger.error("Couldn't validate the components library file {}: {}".format(filename, error))
            sys.exit(1)
            
        try:
            if local:
                run_id = self.threatmodel.run_id
            else:
                run_id = None
            self.component_library.load(data.read_json(filename), run_id)
            logger.debug("Loaded component library from path {}".format(filename))
        except FileNotFoundError:
            pass

    def load_libraries(self):
        self.load_threat_library(data.cwd(), local=True)
        self.load_control_library(data.cwd(), local=True)
        self.load_component_library(data.cwd(), local=True)
        
        for import_path in self.config.imports:
            abs_import_path = data.abs_path(import_path.path)
            if abs_import_path == data.cwd():
                continue  # Local path processed above
            self.load_threat_library(abs_import_path, local=False)
            self.load_control_library(abs_import_path, local=False)
            self.load_component_library(abs_import_path, local=False)
            
    def save_libraries(self):
        data.write_json_pretty(self.threat_library.save(self.threatmodel.run_id), data.cwd(), "threatmodel", "threats.json")
        data.write_json_pretty(self.control_library.save(self.threatmodel.run_id), data.cwd(), "threatmodel", "controls.json")
        data.write_json_pretty(self.component_library.save(self.threatmodel.run_id), data.cwd(), "threatmodel", "components.json")
        
    def load_local_config(self):
        logger.debug("Loading local threatspec.yaml configuration file")
        
        config_path = data.abs_path(data.cwd(), "threatspec.yaml")

        (valid, error) = data.validate_yaml_file(config_path, os.path.join("data", "config_schema.json"))
        if not valid:
            logger.error("Couldn't validate the configation file {}: {}".format("threatspec.yaml", error))
            sys.exit(1)
        self.config.load(data.read_yaml(config_path))

    def init(self):
        logger.info("Initialising threatspec...")

        logger.debug("Creating default configuration file")
        try:
            data.copy_pkg_file(os.path.join("data", "default_config.yaml"), "threatspec.yaml")
        except FileExistsError:
            logger.error("Configuration file already exists, it looks like threatspec has already been initiated here.")
            sys.exit(1)

        self.load_local_config()
        
        logger.debug("Creating directories")
        try:
            data.create_directories(["threatmodel"])
        except IOError as e:
            logger.error("Failed to create directories: {}".format(str(e)))
            raise
        logger.info("""
Threatspec has been initialised. You can now configure the project in this
repository by editing the following file:

    threatspec.yaml
        """)

    def run(self):
        logger.info("Running threatspec...")
        self.load_local_config()
        self.load_libraries()
        self.parse_source(self.config.paths, data.cwd())
        self.save_libraries()
        self.save_threat_model()

        logger.info("""
Threatspec has been run against the source files. The following threat mode file
has been created and contains the mitigations, acceptances, connections etc. for
the project:

    threatmodel/threatmodel.json

The following library files have also been created:

    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json
        """)

    def report(self, output, file=None, template_file=None):
        logger.info("Generating report...")

        self.load_local_config()
        self.load_libraries()
        self.load_threat_models()
        
        report_data = reporter.DataReporter(self.config.project, self.threatmodel)
        
        if output.lower() == "template":
            if not template_file:
                logger.error("Template must be provided for template reports")
                sys.exit(1)
            if not file:
                file = "ThreatModel"
            report = reporter.TemplateReporter(report_data.data)
            report.generate(file, template_file)
            logger.info("The following threat model has been created: {}".format(file))
            
        elif output.lower() == "markdown":
            if not file:
                file = "ThreatModel.md"
        
            png_file = file + ".png"
            gv = reporter.GraphvizReporter(report_data.data)
            gv.generate(file)
            logger.info("The following threat model visualisation image has been created: {}".format(png_file))
        
            report = reporter.MarkdownReporter(report_data.data)
            report.generate(file, image=png_file)
            logger.info("The following threat model markdown report has been created: {}".format(file))
            
        elif output.lower() == "text":
            if not file:
                file = "ThreatModel.txt"
            report = reporter.TextReporter(report_data.data)
            report.generate(file)
            logger.info("The following threat model text file has been created: {}".format(file))

        elif output.lower() == "json":
            if not file:
                file = "ThreatModel.json"
            report = reporter.JsonReporter(report_data.data)
            report.generate(file)
            logger.info("The following threat model JSON file has been created: {}".format(file))

        else:
            logger.error("Invalid report type: {}".format(output))
            sys.exit(1)

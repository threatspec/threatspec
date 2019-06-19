import logging
logger = logging.getLogger(__name__)

import glob, os, sys, uuid
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

    def parse_source(self, paths, parent):
        for config_path in paths:
            abs_path = data.abs_path(parent, config_path.path)
            if abs_path in self.loaded_source_paths:
                continue # Skip as we have already processed this path before
            self.loaded_source_paths[abs_path] = True # We've seen it now
            if data.is_threatspec_path(abs_path):
                logger.debug("Found threatspec.yaml, loading source configuration from {}".format(abs_path))
                new_config = config.Config()
                
                new_config_file = data.abs_path(abs_path, "threatspec.yaml")
                logger.debug("Validating configuration")
                (valid, error) = data.validate_yaml_file(new_config_file, os.path.join("data", "config_schema.json"))
                if not valid:
                    logger.error("Couldn't validate the configation file {}: {}".format(abs_path, error))
                    sys.exit(0)
         
                new_config.load(data.read_yaml(new_config_file))
                self.parse_source(new_config.paths, abs_path)
            else:
                for path in data.recurse_path(abs_path):
                    if data.path_ignored(path, config_path.ignore):
                        logger.debug("Skipping ignored file path: {}".format(path))
                        continue
                    logger.debug("Parsing source files in path {}".format(path))
                    if os.path.isfile(path):
                        self.parser = parser.SourceFileParser(self.threatmodel)
                        self.parser.parse_file(path)
                        """
                        if os.path.splitext(filename)[1].lower() in [".json", ".yaml"]:
                            self.parser = parser.YamlFileParser(self.threatmodel)
                            self.parser.parse_file(filename)
                        else:
                            self.parser = parser.SourceFileParser(self.threatmodel)
                            self.parser.parse_file(filename)
                        """

    def load_threat_model(self, path):
        filename = data.abs_path(path, "threatmodel", "threatmodel.json")
        
        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "threatmodel_schema.json"))
        if not valid:
            logger.error("Couldn't validate the threat model file {}: {}".format(filename, error))
            sys.exit(0)
            
        try:
            self.threatmodel.load(data.read_json(filename))
            logger.debug("Loaded threat model from {}".format(filename))
        except FileNotFoundError:
            pass

    def save_threat_model(self):
        data.write_json_pretty(self.threatmodel.save(), data.cwd(), "threatmodel", "threatmodel.json") # TODO: Unhardcode
    
    def load_threat_library(self, path):
        filename = data.abs_path(path, "threatmodel", "threats.json")
        
        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "threats_schema.json"))
        if not valid:
            logger.error("Couldn't validate the threat library file {}: {}".format(filename, error))
            sys.exit(0)
            
        try:
            self.threat_library.load(data.read_json(filename))
            logger.debug("Loaded threat library from {}".format(filename))
        except FileNotFoundError:
            pass

    def load_control_library(self, path):
        filename = data.abs_path(path, "threatmodel", "controls.json")

        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "controls_schema.json"))
        if not valid:
            logger.error("Couldn't validate the control library file {}: {}".format(filename, error))
            sys.exit(0)
            
        try:
            self.control_library.load(data.read_json(filename))
            logger.debug("Loaded control library from path {}".format(filename))
        except FileNotFoundError:
            pass

    def load_component_library(self, path):
        filename = data.abs_path(path, "threatmodel", "components.json")
        
        logger.debug("Validating {}".format(filename))
        (valid, error) = data.validate_yaml_file(filename, os.path.join("data", "components_schema.json"))
        if not valid:
            logger.error("Couldn't validate the components library file {}: {}".format(filename, error))
            sys.exit(0)
            
        try:
            self.component_library.load(data.read_json(filename))
            logger.debug("Loaded component library from path {}".format(filename))
        except FileNotFoundError:
            pass

    def load_threat_library_data_from_path(self, paths, parent):
        for config_path in paths:
            abs_path = data.abs_path(parent, config_path.path)
            if abs_path in self.loaded_library_paths:
                continue # Skip as we've seen this path before
            self.loaded_library_paths[abs_path] = True # We've seen it now
            if data.is_threatspec_path(abs_path):
                logger.debug("Found threatspec.yaml, loading library from {}".format(abs_path))
                self.load_threat_library(abs_path)
                self.load_control_library(abs_path)
                self.load_component_library(abs_path)
                
                new_config_file = data.abs_path(abs_path, "threatspec.yaml")
                new_config = config.Config()
                
                logger.debug("Validating {}".format(new_config_file))
                (valid, error) = data.validate_yaml_file(new_config_file, os.path.join("data", "config_schema.json"))
                if not valid:
                    logger.error("Couldn't validate the configation file {}: {}".format("threatspec.yaml", error))
                    sys.exit(0)
         
                new_config.load(data.read_yaml(new_config_file))
                self.load_threat_library_data_from_path(new_config.paths, abs_path)

    def load_threat_library_data(self):
        self.load_threat_library_data_from_path(self.config.paths, data.cwd())

    def save_threat_library_data(self):
        data.write_json_pretty(self.threat_library.save(self.threatmodel.run_id), data.cwd(), "threatmodel", "threats.json") # TODO: Unhardcode
        data.write_json_pretty(self.control_library.save(self.threatmodel.run_id), data.cwd(), "threatmodel", "controls.json") # TODO: Unhardcode
        data.write_json_pretty(self.component_library.save(self.threatmodel.run_id), data.cwd(), "threatmodel", "components.json")

    def load_threat_model_data_from_path(self, paths):
        self.load_threat_model(paths)

    def load_threat_model_data(self):
        self.load_threat_model_data_from_path(data.cwd())
        for path in self.config.paths:
            if os.path.dirname(path.path) == data.cwd():
                continue
            base_path = data.glob_to_root(path.path)
            if data.is_threatspec_path(base_path):
                self.load_threat_model_data_from_path(base_path)

    def save_threat_model_data(self):
        self.save_threat_model()

    def generate_report(self):
        self.reporter = reporter.MarkdownReporter(self.config.project, self.threatmodel)
        self.reporter.generate()
        
    def init(self):
        logger.info("Initialising threatspec...")

        logger.debug("Creating default configuration file")
        try:
            data.copy_pkg_file(os.path.join("data","default_config.yaml"), "threatspec.yaml")
        except FileExistsError as e:
            logger.error("Configuration file already exists, it looks like threatspec has already been initiated here.")
            sys.exit(0)

        config_file = data.abs_path(data.cwd(), "threatspec.yaml")
        logger.debug("Validating {}}".format(config_file))
        (valid, error) = data.validate_yaml_file(config_file, os.path.join("data", "config_schema.json"))
        if not valid:
            logger.error("Couldn't validate the configation file {}: {}".format(config_file, error))
            sys.exit(0)
            
        logger.debug("Loading configuration")
        self.config.load(data.read_yaml(config_file))

        logger.debug("Creating directories")
        try:
            data.create_directories(["threatmodel"])
        except IOError as e:
            logger.error("Failed to create directories: {}".format(str(e)))
            raise
        logger.info("""
Threatspec has been initialised. You can now configure the project in this
repository by editing the following file:

    threatspec.yaml.
        """)

    def run(self):
        logger.info("Running threatspec...")
            
        config_path = data.abs_path(data.cwd(), "threatspec.yaml")
        
        logger.debug("Validating configuration")
        (valid, error) = data.validate_yaml_file(config_path, os.path.join("data", "config_schema.json"))
        if not valid:
            logger.error("Couldn't validate the configation file {}: {}".format("threatspec.yaml", error))
            sys.exit(0)
        self.config.load(data.read_yaml(config_path))

        self.load_threat_library_data()
        self.parse_source(self.config.paths, data.cwd())
        self.save_threat_library_data()
        self.save_threat_model_data()

        logger.info("""
Threatspec has been run against the source files. The following threat mode file
has been created and contains the mitigations, acceptances, connections etc. for
the project:

    threatmodel/threatmodel.json

The following library files have also been create:

    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json
        """)

    def report(self):
        logger.info("Generating report...")

        logger.debug("Validating configuration")
        (valid, error) = data.validate_yaml_file("threatspec.yaml", os.path.join("data", "config_schema.json"))
        if not valid:
            logger.error("Couldn't validate the configation file {}: {}".format("threatspec.yaml", error))
            sys.exit(0)
         
        logger.debug("Loading configuration from threatspec.yaml")
        self.config.load(data.read_yaml("threatspec.yaml"))

        self.load_threat_library_data()

        self.load_threat_model_data()

        self.generate_report()

        logger.info("""
The following threat model markdown report has been created:

    ThreatModel.md

The following visualisation image used in the report has also been created:

    ThreatModel.gv.png
        """)

import logging
logger = logging.getLogger(__name__)

import glob, os
from threatspec import config, data, parser, reporter, threatmodel
from pprint import pprint

class ThreatSpecApp():
    
    def __init__(self):
        self.threat_library = threatmodel.ThreatLibrary()
        self.control_library = threatmodel.ControlLibrary()
        self.component_library = threatmodel.ComponentLibrary()

        self.threatmodel = threatmodel.ThreatModel()
        self.threatmodel.threat_library = self.threat_library
        self.threatmodel.control_library = self.control_library
        self.threatmodel.component_library = self.component_library

        self.config = config.Config()
        self.parser = None
        self.reporter = None

    def parse_source(self):
        for config_path in self.config.paths:
            for path in data.recurse_path(config_path.path):
                if data.path_ignored(path, config_path.ignore):
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
        try:
            filename = os.path.join(path, "threatmodel", "threatmodel.json")
            self.threatmodel.load(data.read_json(filename))
            logger.debug("Loaded threat model from {}".format(filename))
        except FileNotFoundError:
            pass

    def save_threat_model(self):
        data.write_json_pretty(self.threatmodel.as_dict(), data.cwd(), "threatmodel", "threatmodel.json") # TODO: Unhardcode
    
    def load_threat_library(self, path):
        try:
            filename = os.path.join(path, "threatmodel", "threats.json")
            self.threat_library.load(data.read_json(filename))
            logger.debug("Loaded threat library from {}".format(filename))
        except FileNotFoundError:
            pass        

    def save_threat_library(self):
        data.write_json_pretty(self.threat_library.as_dict(), data.cwd(), "threatmodel", "threats.json") # TODO: Unhardcode

    def load_control_library(self, path):
        try:
            self.control_library.load(data.read_json(path, "threatmodel", "controls.json"))
            logger.debug("Loaded control library from path {}".format(path))
        except FileNotFoundError:
            pass 

    def save_control_library(self):
        data.write_json_pretty(self.control_library.as_dict(), data.cwd(), "threatmodel", "controls.json") # TODO: Unhardcode

    def load_component_library(self, path):
        try:
            self.component_library.load(data.read_json(path, "threatmodel", "components.json"))
            logger.debug("Loaded component library from path {}".format(path))
        except FileNotFoundError:
            pass 

    def save_component_library(self):
        data.write_json_pretty(self.component_library.as_dict(), data.cwd(), "threatmodel", "components.json") # TODO: Unhardcode
    
    def load_threat_library_data_from_path(self, path):
        logger.debug("Loading threat library from {}".format(path))
        self.load_threat_library(path)
        logger.debug("Loading control library from {}".format(path))
        self.load_control_library(path)
        logger.debug("Loading component library from {}".format(path))
        self.load_component_library(path)

    def load_threat_library_data(self):
        self.load_threat_library_data_from_path(data.cwd())
        for path in self.config.paths:
            if os.path.dirname(path.path) == data.cwd():
                continue
            base_path = data.glob_to_root(path.path)
            if data.is_threatspec_path(base_path):
                self.load_threat_library_data_from_path(base_path)

    def save_threat_library_data(self):
        logger.debug("Saving threat library")
        self.save_threat_library()        
        logger.debug("Saving control library")
        self.save_control_library()
        logger.debug("Saving component library")
        self.save_component_library()

    def load_threat_model_data_from_path(self, path):
        logger.debug("Loading threat model from {}".format(path))
        self.load_threat_model(path)

    def load_threat_model_data(self):
        logger.debug("Loading threat model")
        self.load_threat_model_data_from_path(data.cwd())
        for path in self.config.paths:
            if os.path.dirname(path.path) == data.cwd():
                continue
            base_path = data.glob_to_root(path.path)
            if data.is_threatspec_path(base_path):
                self.load_threat_model_data_from_path(base_path)        

    def save_threat_model_data(self):
        logger.debug("Savinfg threat model")
        self.save_threat_model()

    def generate_report(self):
        self.reporter = reporter.MarkdownReporter(self.config.project, self.threatmodel)
        self.reporter.generate()
        
    def init(self):
        logger.info("Initialising threatspec")

        logger.debug("Creating default configuration file")
        try:
            data.copy_pkg_file("data/default_config.yaml", "threatspec.yaml")
        except FileExistsError as e:
            logger.error("Failed to create the configuration file: {}".format(str(e)))
            raise

        logger.debug("Loading configuration.")
        self.config.load(data.read_yaml("threatspec.yaml"))

        logger.debug("Creating directories")
        try:
            data.create_directories("threatmodel")
        except IOError as e:
            logger.error("Failed to create directories: {}".format(str(e)))
            raise

    def run(self):
        logger.debug("Loading configuration from threatspec.yaml")
        self.config.load(data.read_yaml("threatspec.yaml"))

        logger.info("Loading threat library data")
        self.load_threat_library_data()

        logger.info("Parsing source files")
        self.parse_source()

        logger.info("Saving threat library to threatmodel/")
        self.save_threat_library_data()

        logger.info("Saving threat model to threatmodel/")
        self.save_threat_model_data()

    def report(self):
        logger.debug("Loading configuration from threatspec.yaml")
        self.config.load(data.read_yaml("threatspec.yaml"))

        logger.info("Loading threat library")
        self.load_threat_library_data()

        logger.info("Loading threat model")
        self.load_threat_model_data()

        logger.info("Creating markdown report ThreatModel.md")
        self.generate_report()        

import logging
logger = logging.getLogger(__name__)

import re


class Parser():
    def __init__(self, threatmodel):

        self.threatmodel = threatmodel

        self.action_table = {}
        self.action_table["mitigates"] = self.threatmodel.add_mitigation
        self.action_table["accepts"] = self.threatmodel.add_acceptance
        self.action_table["transfers"] = self.threatmodel.add_transfer
        self.action_table["exposes"] = self.threatmodel.add_exposure
        self.action_table["connects"] = self.threatmodel.add_connection
        self.action_table["review"] = self.threatmodel.add_review
        self.action_table["tests"] = self.threatmodel.add_test

        self.comment_chars = ["//", "#"]

        self.patterns = {}
        self.patterns["mitigates"] = r'@mitigates (?P<component>.*?) against (?P<threat>.*?) with (?P<control>.*)'
        self.patterns["accepts"] = r'@accepts (?P<threat>.*?) to (?P<component>.*?) with (?P<details>.*)'
        self.patterns["transfers"] = r'@transfers (?P<threat>.*?) from (?P<source_component>.*?) to (?P<destination_component>.*?) with (?P<details>.*)'
        self.patterns["exposes"] = r'@exposes (?P<component>.*?) to (?P<threat>.*?) with (?P<details>.*)'
        self.patterns["connects"] = r'@connects (?P<source_component>.*?) (?P<direction>with|to) (?P<destination_component>.*?) with (?P<details>.*)'
        self.patterns["review"] = r'@review (?P<component>.*?) (?P<details>.*)'
        self.patterns["tests"] = r'@tests (?P<control>.*?) for (?P<component>.*)'

    def parse_annotation(self, annotation):
        for action in self.patterns.keys():
            if annotation.startswith("@" + action):
                data = {"action": action}
                pattern = self.patterns[action]
                m = re.match(pattern, annotation, re.M | re.I)
                if m:
                    data.update(m.groupdict())
                    return data
                else:
                    raise RuntimeError("Unable to match annotation '{}' with pattern '{}'".format(annotation, pattern))

    def run_action(self, data, source):
        action = data.pop("action")
        self.action_table[action](**data, source=source)

    def is_threatspec_line(self, line):
        for key in self.patterns.keys():
            if "@{}".format(key) in line:
                return True
        return False


class SourceFileParser(Parser):
    def parse_file(self, filename):
        try:
            with open(filename) as fh:
                lines = fh.readlines()
        except UnicodeDecodeError:
            return
        logger.debug("Parsing file {}".format(filename))
        current_line_index = 0

        while current_line_index < len(lines):
            current_line = lines[current_line_index].strip()
            if self.is_threatspec_line(current_line):
                next_line_index = current_line_index + 1
                while next_line_index < len(lines):
                    next_line = lines[next_line_index].strip()
                    if not self.is_threatspec_line(next_line):
                        logger.debug("Parsing line {}".format(current_line))
                        (data, source) = self.parse_line(current_line, next_line, filename, current_line_index + 1)
                        if data:
                            self.run_action(data, source)
                        break
                    next_line_index += 1
            current_line_index += 1

    def parse_comment_line(self, line):
        annotation = ""
        code = ""
        for commment_char in self.comment_chars:  # TODO: Support files without comments
            if commment_char in line:
                parts = line.split(commment_char)
                annotation = parts[-1].strip()
                code = "".join(parts[0:-1]).strip()
                break
        return (annotation, code)

    def parse_line(self, line, next_line, filename, line_no):
        (annotation, code) = self.parse_comment_line(line)
        if annotation == "":
            return (None, None)
        if code == "":
            code = next_line

        data = self.parse_annotation(annotation)
        if not data:
            return (None, None)
        source = {
            "annotation": annotation,
            "code": code,
            "filename": filename,
            "line": line_no
        }
        return (data, source)


"""
class YamlFileParser(Parser):
    def parse_data(self, data, parent, filename):
        if isinstance(data, dict):
            for k, v in data.items():
                if k == "x-threatspec":
                    for action in self.patterns.keys():
                        if v.startswith("@"+action):
                            self.parse(action, v, str(parent), filename, 0)
                else:
                    self.parse_data(v, data, filename)
        elif isinstance(data, list):
            for v in data:
                self.parse_data(v, data, filename)

    def parse_file(self, filename):
        with open(filename) as fh:
            file_data = yaml.load(fh, Loader=yaml.SafeLoader)
            self.parse_data(file_data, {}, filename)
"""

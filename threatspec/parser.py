import logging
logger = logging.getLogger(__name__)

import re
import yaml
import json
from comment_parser import comment_parser


class Parser():
    def __init__(self, threatmodel):

        self.threatmodel = threatmodel

        self.action_table = {}
        self.action_table["mitigate"] = self.threatmodel.add_mitigation
        self.action_table["accept"] = self.threatmodel.add_acceptance
        self.action_table["transfer"] = self.threatmodel.add_transfer
        self.action_table["expose"] = self.threatmodel.add_exposure
        self.action_table["connect"] = self.threatmodel.add_connection
        self.action_table["review"] = self.threatmodel.add_review
        self.action_table["test"] = self.threatmodel.add_test
        self.action_table["threat"] = self.threatmodel.add_threat
        self.action_table["control"] = self.threatmodel.add_control
        self.action_table["component"] = self.threatmodel.add_component

        self.patterns = {}
        self.patterns["mitigate"] = r'@mitigates? (?P<component>.*?) against (?P<threat>.*?) with (?P<control>.*)'
        self.patterns["accept"] = r'@accepts? (?P<threat>.*?) to (?P<component>.*?) with (?P<details>.*)'
        self.patterns["transfer"] = r'@transfers? (?P<threat>.*?) from (?P<source_component>.*?) to (?P<destination_component>.*?) with (?P<details>.*)'
        self.patterns["expose"] = r'@exposes? (?P<component>.*?) to (?P<threat>.*?) with (?P<details>.*)'
        self.patterns["connect"] = r'@connects? (?P<source_component>.*?) (?P<direction>with|to) (?P<destination_component>.*?) with (?P<details>.*)'
        self.patterns["review"] = r'@reviews? (?P<component>.*?) (?P<details>.*)'
        self.patterns["test"] = r'@tests? (?P<control>.*?) for (?P<component>.*)'
        
        self.patterns["threat"] = r'@threat (?P<threat>.*)'
        self.patterns["control"] = r'@control (?P<control>.*)'
        self.patterns["component"] = r'@component (?P<component>.*)'

    def run_action(self, data, source):
        action = data.pop("action")
        self.action_table[action](data, source=source)
        
    def is_extended(self, line):
        return line[-1] == ":"

    def is_threatspec_line(self, line):
        for key in self.patterns.keys():
            if "@{}".format(key) in line:
                return True
        return False


class CommentParser(Parser):
    def __init__(self, threatmodel, mime=None):
        super().__init__(threatmodel)

    def parse_comment(self, comment):
        annotations = []
        
        LINE = 0
        EXTENDED = 1
        
        state = LINE
        extended_lines = []
        data = None
        
        line_number = 1
        
        for line in comment.split("\n"):
            stripped_line = line.strip()
            if state == LINE:
                for action in self.patterns.keys():
                    if stripped_line.startswith("@" + action):
                        data = {"action": action, "line": line_number, "annotation": stripped_line}
                        extended_lines = []
                        pattern = self.patterns[action]
                        if self.is_extended(stripped_line):
                            state = EXTENDED
                            stripped_line = stripped_line[0:-1]
                        m = re.match(pattern, stripped_line, re.M | re.I)
                        if m:
                            data.update(m.groupdict())
                            if state == LINE:
                                annotations.append(data)
                        else:
                            raise Exception("Could not parse {} pattern:\n{} for comment line:\n{}".format(action, pattern, line))
                            
            elif state == EXTENDED:
                if stripped_line == "":
                    state = LINE
                    extended_text = "\n".join(extended_lines)
                    data["annotation"] += "\n" + extended_text
                    data.update(yaml.load(extended_text, Loader=yaml.SafeLoader))
                    annotations.append(data)
                else:
                    extended_lines.append(line)
                    
            line_number += 1
        return annotations
    

class TextFileParser(CommentParser):
    def parse_file(self, filename):
        logger.debug("Parsing file {}".format(filename))

        with open(filename) as fh:
            data = fh.read()
        
        source = {
            "filename": filename,
            "code": ""
        }
        
        for data in self.parse_comment(data):
            source["annotation"] = data.pop("annotation")
            source["line"] = data.pop("line")
            self.run_action(data, source)

    
class SourceFileParser(CommentParser):
    
    def __init__(self, threatmodel, mime=None):
        super().__init__(threatmodel)
        self.mime = mime

    def extract_comment_context(self, lines, commented_lines, start_line, num_lines, multiline=False):
        count = 0
        i = start_line
        code = []
        
        capture_first_line = not multiline
            
        for line in lines[start_line - 1:]:
            if count >= num_lines:
                return "".join(code)
            
            if capture_first_line:
                code.append(line)
                capture_first_line = False
                
            if i not in commented_lines:
                code.append(line)
                count += 1
            i += 1
        return "".join(code)
    
    def get_lines(self, filename):
        try:
            with open(filename) as fh:
                return fh.readlines()
        except UnicodeDecodeError:
            return None
        
    def parse_file(self, filename):
        logger.debug("Parsing file {}".format(filename))
        
        lines = self.get_lines(filename)
        if not lines:
            return
        
        commented_line_numbers = []
        comments = []
        try:
            for comment in comment_parser.extract_comments(filename, self.mime):
                comment_text = comment.text()
                comment_line = comment.line_number()
                if comment.is_multiline():
                    offset = len(comment_text.split("\n"))
                    commented_line_numbers += range(comment_line, comment_line + offset)
                else:
                    offset = 0
                    commented_line_numbers.append(comment_line)
                comments.append({
                    "text": comment_text,
                    "line": comment_line,
                    "offset": offset,
                    "multiline": comment.is_multiline()
                })
        except comment_parser.UnsupportedError as e:
            print(e)
            return
                
        for comment in comments:
            comment["text"] = comment["text"].strip()
            num_lines = 5  # Get 5 lines of code
            code = self.extract_comment_context(lines, commented_line_numbers, comment["line"] + comment["offset"], num_lines, comment["multiline"])

            source = {
                "code": code,
                "filename": filename
            }

            annotations = self.parse_comment(comment["text"])
            if annotations:
                for data in annotations:
                    source["line"] = data.pop("line")
                    source["annotation"] = data.pop("annotation")
                    self.run_action(data, source)


class YamlFileParser(Parser):
    def parse_annotation(self, annotation, data={}):
        stripped_line = annotation.strip()
        for action in self.patterns.keys():
            if stripped_line.startswith("@" + action):
                data["action"] = action
                pattern = self.patterns[action]
                m = re.match(pattern, stripped_line, re.M | re.I)
                if m:
                    data.update(m.groupdict())
                    return data
                else:
                    raise Exception("Could not parse {} pattern:\n{} for comment line:\n{}".format(action, pattern, stripped_line))
                
    def parse_key(self, data, parent, filename):
        if isinstance(data, str):
            annotation = self.parse_annotation(data)
            source = {
                "annotation": data,
                "code": json.dumps(parent, indent=2),
                "filename": filename,
                "line": 0
            }
            self.run_action(annotation, source)
        elif isinstance(data, list):
            for v in data:
                if not isinstance(v, str):
                    raise Exception("Invalid value type for x-threatspec list in {}".format(filename))
                annotation = self.parse_annotation(v)
                source = {
                    "annotation": v,
                    "code": json.dumps(parent, indent=2),
                    "filename": filename,
                    "line": 0
                }
                self.run_action(annotation, source)
        elif isinstance(data, dict):
            for k, v in data.items():
                annotation = self.parse_annotation(k, v)
                source = {
                    "annotation": k,
                    "code": json.dumps(parent, indent=2),
                    "filename": filename,
                    "line": 0
                }
                self.run_action(annotation, source)

    def parse_data(self, data, parent, filename):
        if isinstance(data, dict):
            for k, v in data.items():
                if k == "x-threatspec":
                    self.parse_key(v, data, filename)
                else:
                    self.parse_data(v, data, filename)
        elif isinstance(data, list):
            for v in data:
                self.parse_data(v, data, filename)
    
    def parse_file(self, filename):
        logger.debug("Parsing file {}".format(filename))
        with open(filename) as fh:
            file_data = yaml.load(fh, Loader=yaml.SafeLoader)
            self.parse_data(file_data, {}, filename)

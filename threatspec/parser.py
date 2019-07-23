import logging
logger = logging.getLogger(__name__)

import re
import yaml
from comment_parser import comment_parser
from pprint import pprint

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
        self.action_table["threat"] = self.threatmodel.add_threat
        self.action_table["control"] = self.threatmodel.add_control
        self.action_table["component"] = self.threatmodel.add_component

        self.patterns = {}
        self.patterns["mitigates"] = r'@mitigates (?P<component>.*?) against (?P<threat>.*?) with (?P<control>.*)'
        self.patterns["accepts"] = r'@accepts (?P<threat>.*?) to (?P<component>.*?) with (?P<details>.*)'
        self.patterns["transfers"] = r'@transfers (?P<threat>.*?) from (?P<source_component>.*?) to (?P<destination_component>.*?) with (?P<details>.*)'
        self.patterns["exposes"] = r'@exposes (?P<component>.*?) to (?P<threat>.*?) with (?P<details>.*)'
        self.patterns["connects"] = r'@connects (?P<source_component>.*?) (?P<direction>with|to) (?P<destination_component>.*?) with (?P<details>.*)'
        self.patterns["review"] = r'@review (?P<component>.*?) (?P<details>.*)'
        self.patterns["tests"] = r'@tests (?P<control>.*?) for (?P<component>.*)'
        
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


class SourceFileParser(Parser):
    
    def __init__(self, threatmodel, mime=None):
        super().__init__(threatmodel)
        self.mime = mime
    
    def parse_comment(self, comment):
        annotations = []
        
        LINE = 0
        EXTENDED = 1
        
        state = LINE
        extended_lines = []
        data = None
        
        for line in comment.split("\n"):
            stripped_line = line.strip()
            if state == LINE:
                for action in self.patterns.keys():
                    if stripped_line.startswith("@" + action):
                        data = {"action": action}
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
                    data.update(yaml.load(extended_text, Loader=yaml.SafeLoader))
                    annotations.append(data)
                else:
                    extended_lines.append(line)
        return annotations
    
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
                "annotation": comment["text"],
                "code": code,
                "filename": filename,
                "line": comment["line"]
            }

            annotations = self.parse_comment(comment["text"])
            if annotations:
                for data in annotations:
                    self.run_action(data, source)


class YamlFileParser(Parser):
    def parse_file(self, filename):
        pass
    
    
class JsonFileParser(Parser):
    def parse_file(self, filename):
        pass
    
    
class TextFileParser(Parser):
    def parse_file(self, filename):
        pass
    

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

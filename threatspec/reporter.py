import logging
logger = logging.getLogger(__name__)

from threatspec import data, threatmodel, config
from jinja2 import Environment, FileSystemLoader, PackageLoader
from graphviz import Digraph
import os
import uuid
import textwrap


def random_id():
    return uuid.uuid4().hex


def left_align(text):
    return text.replace("\n", "\l")


def right_align(text):
    return text.replace("\n", "\r")
    
    
def wrap(text, width):
    return textwrap.fill(text, width)
    
    
def trunc_left(text, width):
    if len(text) > width:
        start = len(text) - (width - 3)
        return "..." + text[start:]
    else:
        return text


def trunc_right(text, width):
    if len(text) > width:
        return text[0:width - 3] + "..."
    else:
        return text


def join(first, second):
    if first == "":
        return ""
    elif first[-1] == ".":
        joiner = " "
    else:
        joiner = ". "
    return (first + joiner + second).strip()
    
        
def code(block, width=None):
    new_lines = []
    lines = block.split("\n")
    num_spaces = 0
    for line in lines:
        if line.strip() == "":
            continue
        else:
            num_spaces = len(line) - len(line.lstrip(' '))
            break
        
    for line in lines:
        if width:
            new_lines.append(trunc_right(line[num_spaces:], width))
        else:
            new_lines.append(line[num_spaces:])
    return "\n".join(new_lines)


class DataReporter():
    
    def __init__(self, project: config.Project, threatmodel: threatmodel.ThreatModel):
        self.project = project
        self.threatmodel = threatmodel
        self.data = None
        self.build_report()

    def build_report(self):
        threat_library = self.threatmodel.threat_library.save()
        control_library = self.threatmodel.control_library.save()
        component_library = self.threatmodel.component_library.save()
        
        self.data = {
            "project": {
                "name": self.project.name,
                "description": self.project.description
            },
            "threatmodel": self.threatmodel.save(),
            "threats": {},
            "controls": {},
            "components": {}
        }
        
        tests_by_component_control = {}
        for test in self.data["threatmodel"]["tests"]:
            component_id = test["component"]
            control_id = test["control"]
            
            if component_id in component_library["components"]:
                test["component"] = component_library["components"][component_id]
                if component_id not in self.data["components"]:
                    self.data["components"][component_id] = component_library["components"][component_id]
            if component_id not in tests_by_component_control:
                tests_by_component_control[component_id] = {}
            
            if control_id in control_library["controls"]:
                test["control"] = control_library["controls"][control_id]
                if control_id not in self.data["controls"]:
                    self.data["controls"][control_id] = control_library["controls"][control_id]
            if control_id not in tests_by_component_control[component_id]:
                tests_by_component_control[component_id][control_id] = []
                
            tests_by_component_control[component_id][control_id].append(test)
        
        for key, arr in self.data["threatmodel"].items():
            if key == "tests":
                continue  # Tests are processed separately above
            if isinstance(arr, list):
                for obj in arr:
                    if not isinstance(obj, dict):
                        continue
                    
                    if "tests" not in obj:
                        obj["tests"] = []
                        
                    if "threat" in obj:
                        threat_id = obj["threat"]
                        if threat_id in threat_library["threats"]:
                            obj["threat"] = threat_library["threats"][threat_id]
                            if threat_id not in self.data["threats"]:
                                self.data["threats"][threat_id] = threat_library["threats"][threat_id]

                    control_id = None
                    if "control" in obj:
                        control_id = obj["control"]
                        if control_id in control_library["controls"]:
                            obj["control"] = control_library["controls"][control_id]
                            if control_id not in self.data["controls"]:
                                self.data["controls"][control_id] = control_library["controls"][control_id]
                            
                    for component_key in ["component", "source_component", "destination_component"]:
                        if component_key in obj:
                            component_id = obj[component_key]
                            if component_id in component_library["components"]:
                                obj[component_key] = component_library["components"][component_id]
                                if component_id not in self.data["components"]:
                                    self.data["components"][component_id] = component_library["components"][component_id]
                                
                                if component_id in tests_by_component_control and control_id in tests_by_component_control[component_id]:
                                    obj["tests"] += tests_by_component_control[component_id][control_id]


class Reporter():
    
    def __init__(self, data):
        self.data = data


class TemplateReporter(Reporter):
    def generate(self, filename, template_path):
        
        template_dir = os.path.dirname(template_path)
        template_file = os.path.basename(template_path)
        
        template_loader = FileSystemLoader(template_dir)
        template_env = Environment(loader=template_loader)
        template = template_env.get_template(template_file)
        
        data.write_file(template.render(report=self.data), filename)

        
class MarkdownReporter(Reporter):

    def generate(self, filename, image=None):
        template_loader = PackageLoader('threatspec', 'report_templates')
        template_env = Environment(loader=template_loader)
        template = template_env.get_template('default_markdown.md')

        data.write_file(template.render(report=self.data, image=image), filename)


class JsonReporter(Reporter):
    
    def generate(self, filename):
        data.write_json_pretty(self.data, filename)


class TextReporter(Reporter):
    
    def generate(self, filename):
        template_loader = PackageLoader('threatspec', 'report_templates')
        template_env = Environment(loader=template_loader)
        template = template_env.get_template('default_text.txt')

        data.write_file(template.render(report=self.data), filename)
        

class Graph():
    def __init__(self, title):
        self.dot = Digraph(comment=title,  # TODO: Unhardcode
            engine='dot',
            format='png',
            graph_attr={
                'rankdir': 'LR'
            },
            node_attr={
                'fontcolor': '#2f3640',
                'shape': 'rect',
                'fontsize': '10',
                'fontname': 'Helvetica'
            },
            edge_attr={
                'fontcolor': '#2f3640',
                'fontsize': '10',
                'fontname': 'Helvetica'
            }
        )


class GraphvizReporter(Reporter):

    def __init__(self, data):
        super().__init__(data)
        self.graph = Graph(self.data["project"]["name"])
        self.nodes = {}
        self.edges = {}
        
        red = "#c0392b"
        green = "#27ae60"
        blue = "#3498db"
        orange = "#f39c12"
        purple = "#8e44ad"
        pink = "#f368e0"
        grey = "#3d3d3d"
        topaz = "#0fb9b1"
        
        self.config = {
            "threat":                    { "color": red },
            "control":                   { "color": green },
            "component":                 { "color": blue,
                                           "penwidth": "2",
                                           "shape": "oval" },
            "component_edge":            { "color": blue,
                                           "penwidth": "1",
                                           "style": "dotted" },
            "mitigation":                { "color": green },
            "acceptance":                { "color": orange },
            "exposure":                  { "color": red },
            "transfer":                  { "color": purple },
            "review":                    { "color": pink },
            "test":                      { "color": topaz },
            "threat_control_edge":       { "color": orange,
                                           "arrowhead": "none" },
            "threat_component_edge":     { "color": red },
            "threat_exposure_edge":      { "color": red,
                                           "arrowhead": "none" },
            "threat_transfer_edge":      { "color": purple,
                                           "arrowhead": "none" },
            "threat_acceptance_edge":    { "color": red,
                                           "arrowhead": "none" },
            "threat_mitigation_edge":    { "color": green,
                                           "arrowhead": "none" },
            "control_mitigation_edge":   { "color": green,
                                           "arrowhead": "none" },
            "exposure_component_edge":   { "color": red },
            "acceptance_component_edge": { "color": orange },
            "source_transfer_edge":      { "color": orange,
                                           "arrowhead": "none" },
            "transfer_dest_edge":        { "color": red },
            "mitigation_component_edge": { "color": green },
            "review_component_edge":     { "color": pink },
            "connection_edge":           { "color": grey,
                                           "penwidth": "2" },
            "control_test_edge":         { "color": topaz,
                                           "arrowhead": "none" },
            "test_component_edge":       { "color": topaz }
        }
        self.node_width = 80
            
    def add_node(self, node_id, node_name, config):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "label": node_name,
                "config": config
            }
       
    def add_edge(self, source_node_id, destination_node_id, config):
        if source_node_id not in self.edges:
            self.edges[source_node_id] = {}
        if destination_node_id not in self.edges[source_node_id]:
            self.edges[source_node_id][destination_node_id] = config

    def render(self, filename):
        for node_id, node in self.nodes.items():
            self.graph.dot.node(node_id, node["label"], **node["config"])
            
        for source_node_id in self.edges.keys():
            for destination_node_id, cfg in self.edges[source_node_id].items():
                self.graph.dot.edge(source_node_id, destination_node_id, **cfg)
            
        self.graph.dot.render(filename, cleanup=True)

    def process_threats(self):
        for threat_id, threat in self.data["threats"].items():
            if threat["description"]:
                threat_label = "Threat\n\n{}\n\n{}".format(
                    threat["name"].title(),
                    left_align(wrap(threat["description"], self.node_width))
                )
            else:
                threat_label = "Threat\n\n{}".format(threat["name"].title())
            self.add_node(threat_id, threat_label, self.config["threat"])
            
    def process_controls(self):
        for control_id, control in self.data["controls"].items():
            if control["description"]:
                control_label = "Control\n\n{}\n\n{}".format(
                    control["name"].title(),
                    left_align(wrap(control["description"], self.node_width))
                )
            else:
                control_label = "Control\n\n{}".format(control["name"].title())
                
            self.add_node(control_id, control_label, self.config["control"])
            
    def process_components(self):
        for component_id, component in self.data["components"].items():
            self.add_node(component_id, "{}".format(component["name"]), self.config["component"])

            for path in component["paths"]:
                i = 0
                while i < len(path) - 1:
                    source_component = path[i]
                    destination_component = path[i + 1]

                    self.add_node(source_component, "{}".format(source_component), self.config["component"])
                    self.add_edge(source_component, destination_component, self.config["component_edge"])
                    i += 1
                if len(path) > 0:
                    last_component = path[-1]
                    self.add_node(last_component, "{}".format(last_component), self.config["component"])
                    self.add_edge(last_component, component_id, self.config["component_edge"])

    def process_mitigations(self):
        for mitigation in self.data["threatmodel"]["mitigations"]:
            mitigation_id = random_id()
            control = join(mitigation["control"]["name"].title(), mitigation["control"]["description"])

            mitigation_label = "{}\n\n{}\n\nin {}:{}".format(
                wrap("Threat is mitigated by control {}".format(control), self.node_width),
                left_align(code(mitigation["source"]["code"], self.node_width - 10)),
                trunc_left(mitigation["source"]["filename"], self.node_width - 10),
                str(mitigation["source"]["line"])
            )
            self.add_node(mitigation_id, mitigation_label, self.config["mitigation"])
            
            self.add_edge(mitigation["threat"]["id"], mitigation_id, self.config["threat_mitigation_edge"])
            self.add_edge(mitigation["control"]["id"], mitigation_id, self.config["control_mitigation_edge"])
            self.add_edge(mitigation_id, mitigation["component"]["id"], self.config["mitigation_component_edge"])
            
    def process_acceptances(self):
        for acceptance in self.data["threatmodel"]["acceptances"]:
            acceptance_id = random_id()

            acceptance_label = "{}\n\n{}\n\nin {}:{}".format(
                wrap("Threat has been accepted by {}".format(acceptance["details"]), self.node_width),
                left_align(code(acceptance["source"]["code"], self.node_width - 10)),
                trunc_left(acceptance["source"]["filename"], self.node_width - 10),
                str(acceptance["source"]["line"])
            )
            
            self.add_node(acceptance_id, acceptance_label, self.config["acceptance"])
            
            self.add_edge(acceptance["threat"]["id"], acceptance_id, self.config["threat_acceptance_edge"])
            self.add_edge(acceptance_id, acceptance["component"]["id"], self.config["acceptance_component_edge"])
    
    def process_exposures(self):
        for exposure in self.data["threatmodel"]["exposures"]:
            exposure_id = random_id()
            
            exposure_label = "{}\n\n{}\n\nin {}:{}".format(
                wrap("Threat is exposed by {}".format(exposure["details"]), self.node_width),
                left_align(code(exposure["source"]["code"], self.node_width - 10)),
                trunc_left(exposure["source"]["filename"], self.node_width - 10),
                str(exposure["source"]["line"])
            )
            
            self.add_node(exposure_id, exposure_label, self.config["exposure"])
            
            self.add_edge(exposure["threat"]["id"], exposure_id, self.config["threat_exposure_edge"])
            self.add_edge(exposure_id, exposure["component"]["id"], self.config["exposure_component_edge"])
            
    def process_transfers(self):
        for transfer in self.data["threatmodel"]["transfers"]:
            transfer_id = random_id()
            
            transfer_label = "{}\n\n{}\n\nin {}:{}".format(
                wrap("Threat is transfered to another component by {}".format(transfer["details"]), self.node_width),
                left_align(code(transfer["source"]["code"], self.node_width - 10)),
                trunc_left(transfer["source"]["filename"], self.node_width - 10),
                str(transfer["source"]["line"])
            )
            
            self.add_node(transfer_id, transfer_label, self.config["transfer"])
            
            self.add_edge(transfer["threat"]["id"], transfer_id, self.config["threat_transfer_edge"])
            self.add_edge(transfer["source_component"]["id"], transfer_id, self.config["source_transfer_edge"])
            self.add_edge(transfer_id, transfer["destination_component"]["id"], self.config["transfer_dest_edge"])
    
    def process_reviews(self):
        for review in self.data["threatmodel"]["reviews"]:
            review_id = random_id()
            review_label = "{}\n\n{}\n\nin {}:{}".format(
                wrap("To review: {}".format(review["details"]), self.node_width),
                left_align(code(review["source"]["code"], self.node_width - 10)),
                trunc_left(review["source"]["filename"], self.node_width - 10),
                str(review["source"]["line"])
            )
            self.add_node(review_id, review_label, self.config["review"])
            
            self.add_edge(review_id, review["component"]["id"], self.config["review_component_edge"])
    
    def process_connections(self):
        for connection in self.data["threatmodel"]["connections"]:
            cfg = self.config["connection_edge"].copy()
            cfg["label"] = connection["details"]
            self.add_edge(connection["source_component"]["id"], connection["destination_component"]["id"], cfg)
    
    def process_tests(self):
        for test in self.data["threatmodel"]["tests"]:
            test_id = random_id()
            
            test_label = "Control is tested for component\n\n{}\n\nin {}:{}".format(
                left_align(code(test["source"]["code"], self.node_width - 10)),
                trunc_left(test["source"]["filename"], self.node_width - 10),
                str(test["source"]["line"])
            )
            self.add_node(test_id, test_label, self.config["test"])
            
            self.add_edge(test["control"]["id"], test_id, self.config["control_test_edge"])
            self.add_edge(test_id, test["component"]["id"], self.config["test_component_edge"])

    def generate(self, filename):
        self.process_threats()
        self.process_controls()
        self.process_components()
        
        self.process_mitigations()
        self.process_acceptances()
        self.process_exposures()
        self.process_transfers()
        
        self.process_reviews()
        self.process_connections()
        self.process_tests()
        
        self.render(filename)

import re, uuid
from threatspec import data, threatmodel, config
from pprint import pprint
from graphviz import Digraph

class Reporter():
    def __init__(self, project: config.Project, threatmodel: threatmodel.ThreatModel):
        self.project = project
        self.threatmodel = threatmodel

        self.components = {}
        self.component_pairs: {}

    def random_id(self):
        return uuid.uuid4().hex

    def to_id(self, text):
        if text.endswith("/"):
            text += "root"
        return "#" + re.sub('[^a-z0-9_]+', '_', text.strip().lower().replace('-','')).strip('_')

    def parse_component_paths(self):
        self.components = {}
        self.component_pairs = {}

        for id, component in self.threatmodel.component_library.components.items():
            self.components[id] = component.name.split(":")[-1] # Dirty hack
            for path in component.paths:
                if not path:
                    continue

                i = 0
                while i < len(path)-1:
                    source_component = path[i]
                    source_component_id = self.to_id(source_component)
                    destination_component = path[i+1]
                    destination_component_id = self.to_id(destination_component)

                    if not source_component_id in self.components:
                        self.components[source_component_id] = source_component
                    if not destination_component_id in self.components:
                        self.components[destination_component] = destination_component

                    if source_component_id not in self.component_pairs:
                        self.component_pairs[source_component_id] = {}
                    if destination_component_id not in self.component_pairs[source_component_id]:
                        self.component_pairs[source_component_id][destination_component_id] = 1
                    else:
                        self.component_pairs[source_component_id][destination_component_id] +=1
                    i += 1
            
                last_component = path[-1]
                last_component_id = self.to_id(last_component)

                if last_component_id not in self.components:
                    self.components[last_component_id] = last_component
                
                if last_component_id not in self.component_pairs:
                    self.component_pairs[last_component_id] = {}
                if id not in self.component_pairs[last_component_id]:
                    self.component_pairs[last_component_id][id] = 1
                else:
                    self.component_pairs[last_component_id][id] += 1


class MarkdownTable():
    def __init__(self):
        self.headers = []
        self.rows = []

    def add_headers(self, headers):
        self.headers = headers

    def add_row(self, row):
        self.rows.append(row)

class Markdown():
    def __init__(self):
        self.data = ""

    def add_h1(self, text):
        self.data += "# {}\n\n".format(text)

    def add_paragraph(self, text):
        self.data += "{}\n\n".format(text)

    def add_image(self, alt, file, title):
        self.data += "![{}]({} \"{}\")\n\n".format(alt, file, title)

    def add_table(self, table):
        self.data += "| {} |\n".format(" | ".join(table.headers))
        self.data += "| {} |\n".format(" | ".join("---" for x in table.headers))
        for row in table.rows:
            self.data += "| {} |\n".format(" | ".join(row))
        self.data += "\n\n"

    def code(self, text):
        return "`{}`".format(text)

    def code_block(self, text):
        return "```\n{}\n```".format(text)


class Graph():
    def __init__(self, title):
        self.dot = Digraph(comment=title, # TODO: Unhardcode
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

class MarkdownReporter(Reporter):
        
    def generate(self):
        self.parse_component_paths()

        self.graph = Graph(self.project.name)
        self.report = Markdown()
        self.report.add_h1(self.project.name) # TODO: Unhardcode
        self.report.add_paragraph(self.project.description)

        self.report.add_h1("Diagram")
        self.report.add_image("Diagram", "ThreatModel.png", "Threat Model Diagram")

        # Tests
        tests_by_component_control = {}
        for test in self.threatmodel.tests:
            component_id = test.component
            control_id = test.control

            if component_id not in tests_by_component_control:
                tests_by_component_control[component_id] = {}
            if control_id not in tests_by_component_control[component_id]:
                tests_by_component_control[component_id][control_id] = test

        # Components
        for component_id, component in self.components.items():
            self.graph.dot.node(component_id, component, color='#3498db')

        for comp_a_id in self.component_pairs:
            for comp_b_id in self.component_pairs[comp_a_id]:
                self.graph.dot.edge(comp_a_id, comp_b_id, color='#a3cdf7')

        # Threats
        for threat_id, threat in self.threatmodel.threat_library.threats.items():
            self.graph.dot.node(threat_id, "Threat\n{}\n\n{}".format(threat_id, threat.name), color='#c0392b')

        # Controls
        for control_id, control in self.threatmodel.control_library.controls.items():
            self.graph.dot.node(control_id, "Control\n{}\n\n{}".format(control_id, control.name), color='#27ae60')

        self.report.add_h1("Threats")

        table = MarkdownTable()
        table.add_headers(["Type", "Component", "Threat", "Description", "Test", "Test File", "File", "Line", "Source"])

        # Exposes
        for exposure in self.threatmodel.exposures:
            exposure_id = self.random_id()
            threat_id = exposure.threat
            threat = self.threatmodel.threat_library.threats[threat_id]
            component_id = exposure.component
            component = self.threatmodel.component_library.components[component_id]

            self.graph.dot.node(exposure_id, "Exposure\n\n{}".format(exposure.details), color='#c0392b')
            #dot.edge(threat["name"], component["name"], color='#c0392b', concentrate='true')
            #dot.edge(exposure["exposure"], threat["name"], color='#c0392b', concentrate='true')
            self.graph.dot.edge(exposure_id, component_id, color='#c0392b', concentrate='true')
            self.graph.dot.edge(threat_id, exposure_id, color='#c0392b', concentrate='true')

            table.add_row([
                "Exposure",
                component.name,
                threat.name,
                exposure.details,
                "",
                "",
                exposure.source.filename,
                str(exposure.source.line),
                self.report.code(exposure.source.code)
            ])

        # Acceptances
        for acceptance in self.threatmodel.acceptances:
            acceptance_id = self.random_id()
            threat_id = acceptance.threat
            threat = self.threatmodel.threat_library.threats[threat_id]
            component_id = acceptance.component
            component = self.threatmodel.component_library.components[component_id]

            self.graph.dot.node(acceptance_id, "Accepts\n\n{}".format(acceptance.details), color='#c0392b')
            self.graph.dot.edge(threat_id, component_id, color='#c0392b', concentrate='true')
            self.graph.dot.edge(acceptance_id, threat_id, color='#c0392b', concentrate='true')

            table.add_row([
                "Acceptance",
                component.name,
                threat.name,
                acceptance.details,
                "",
                "",
                acceptance.source.filename,
                str(acceptance.source.line),
                self.report.code(acceptance.source.code)
            ])

        # Transfers
        for transfer in self.threatmodel.transfers:
            transfer_id = self.random_id()
            threat_id = transfer.threat
            threat = self.threatmodel.threat_library.threats[threat_id]
            source_id = transfer.source_component
            source = self.threatmodel.component_library.components[source_id]
            dest_id = transfer.destination_component
            dest = self.threatmodel.component_library.components[dest_id]

            self.graph.dot.node(transfer_id, "Transfer\n\n{}".format(transfer.details), color='#8e44ad')

            #dot.edge(source["name"], threat["name"], color='#f39c12', concentrate='true')
            #dot.edge(threat["name"], dest["name"], color='#e74c3c', concentrate='true')
            #dot.edge(transfer["transfer"], threat["name"], color='#8e44ad', concentrate='true')
            
            self.graph.dot.edge(source_id, transfer_id, color='#f39c12', concentrate='true')
            self.graph.dot.edge(transfer_id, dest_id, color='#e74c3c', concentrate='true')
            self.graph.dot.edge(threat_id, transfer_id, color='#8e44ad', concentrate='true')

            table.add_row(
                ["Transfer",
                "{} (from {})".format(dest.name, source.name),
                threat.name,
                transfer.details,
                "",
                "",
                transfer.source.filename,
                str(transfer.source.line),
                self.report.code(transfer.source.code)
            ])

        # Mitigations
        for mitigation in self.threatmodel.mitigations:
            component_id = mitigation.component
            component = self.threatmodel.component_library.components[component_id]
            threat_id = mitigation.threat
            threat = self.threatmodel.threat_library.threats[threat_id]
            control_id = mitigation.control
            control = self.threatmodel.control_library.controls[control_id]

            #dot.edge(threat["name"], component["name"], color='#f39c12', concentrate='true')
            #dot.edge(control["name"], threat["name"], color='#27ae60', concentrate='true')
            
            self.graph.dot.edge(control_id, component_id, color='#27ae60', concentrate='true')
            self.graph.dot.edge(threat_id, control_id, color='#f39c12', concentrate='true')

            if component_id in tests_by_component_control and control_id in tests_by_component_control[component_id]:
                test = tests_by_component_control[component_id][control_id]
                test_field = self.report.code(test.source.code)
                test_line = "{}:{}".format(test.source.filename, str(test.source.line))
            else:
                test_field = "None"
                test_line = ""

            table.add_row([
                "Mitigation",
                component.name,
                threat.name,
                control.name,
                test_field,
                test_line,
                mitigation.source.filename,
                str(mitigation.source.line),
                self.report.code(mitigation.source.code)
            ])

        # Create the threats table
        self.report.add_table(table)

        # Connects
        self.report.add_h1("Connections")
        table = MarkdownTable()
        table.add_headers(["Source", "Destination", "Description", "File", "Line", "Source"])

        for connection in self.threatmodel.connections:
            source_id = connection.source_component
            source = self.threatmodel.component_library.components[source_id]
            dest_id = connection.destination_component
            dest = self.threatmodel.component_library.components[dest_id]

            self.graph.dot.edge(source_id, dest_id, label=connection.details, concentrate='true')

            table.add_row([
                source.name,
                dest.name,
                connection.details,
                connection.source.filename,
                str(connection.source.line),
                self.report.code(connection.source.code)
            ])

        self.report.add_table(table)

        # Reviews
        self.report.add_h1("Reviews")
        table = MarkdownTable()
        table.add_headers(["Component", "Review", "File", "Line", "Source"])

        for review in self.threatmodel.reviews:
            review_id = self.random_id()
            component_id = review.component
            component = self.threatmodel.component_library.components[component_id]

            self.graph.dot.node(review_id, review.details)
            self.graph.dot.edge(review_id, component_id)

            table.add_row([
                component.name,
                review.details,
                review.source.filename,
                str(review.source.line),
                self.report.code(review.source.code)
            ])

        self.report.add_table(table)

        # Outputs
        self.graph.dot.render('ThreatModel.gv')
        data.write_file(self.report.data, "ThreatModel.md")

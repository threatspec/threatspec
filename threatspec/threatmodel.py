from typing import List, Dict
import re


class Source():
    def __init__(self, annotation: str, code: str, filename: str, line: int):
        self.annotation = annotation
        self.code = code
        self.filename = filename
        self.line = line
        
    def as_dict(self):
        return {
            "annotation": self.annotation,
            "code": self.code,
            "filename": self.filename,
            "line": self.line
        }


class Threat():
    def __init__(self, id: str, run_id: str, name: str, description: str):
        self.id = id
        self.run_id = run_id
        self.name = name
        self.description = description

    def as_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "name": self.name,
            "description": self.description
        }


class Control():
    def __init__(self, id: str, run_id: str, name: str, description: str):
        self.id = id
        self.run_id = run_id
        self.name = name
        self.description = description
        
    def as_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "name": self.name,
            "description": self.description
        }


class Component():
    def __init__(self, id: str, run_id: str, name: str, description: str, paths: List[str]):
        self.id = id
        self.run_id = run_id
        self.name = name
        self.description = description
        self.paths = paths

    def as_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "name": self.name,
            "description": self.description,
            "paths": self.paths
        }


class Mitigation():
    def __init__(self, control: Control, threat: Threat, component: Component, source: Source):
        self.control = control
        self.threat = threat
        self.component = component
        self.source = source
        
    def as_dict(self):
        return {
            "control": self.control,
            "threat": self.threat,
            "component": self.component,
            "source": self.source.as_dict()
        }


class Acceptance():
    def __init__(self, threat: Threat, component: Component, details: str, source: Source):
        self.threat = threat
        self.component = component
        self.details = details
        self.source = source
        
    def as_dict(self):
        return {
            "threat": self.threat,
            "component": self.component,
            "details": self.details,
            "source": self.source.as_dict()
        }


class Transfer():
    def __init__(self, threat: Threat, source_component: Component, destination_component: Component, details: str, source: Source):
        self.threat = threat
        self.source_component = source_component
        self.destination_component = destination_component
        self.details = details
        self.source = source
        
    def as_dict(self):
        return {
            "threat": self.threat,
            "source_component": self.source_component,
            "destination_component": self.destination_component,
            "details": self.details,
            "source": self.source.as_dict()
        }


class Exposure():
    def __init__(self, threat: Threat, component: Component, details: str, source: Source):
        self.threat = threat
        self.component = component
        self.details = details
        self.source = source
    
    def as_dict(self):
        return {
            "threat": self.threat,
            "component": self.component,
            "details": self.details,
            "source": self.source.as_dict()
        }


class Connection():
    def __init__(self, source_component: Component, destination_component: Component, direction: str, details: str, source: Source):
        self.source_component = source_component
        self.destination_component = destination_component
        self.direction = direction
        self.details = details
        self.source = source
        
    def as_dict(self):
        return {
            "source_component": self.source_component,
            "destination_component": self.destination_component,
            "direction": self.direction,
            "details": self.details,
            "source": self.source.as_dict()
        }


class Review():
    def __init__(self, component: Component, details: str, source: Source):
        self.component = component
        self.details = details
        self.source = source

    def as_dict(self):
        return {
            "component": self.component,
            "details": self.details,
            "source": self.source.as_dict()
        }


class Test():
    def __init__(self, component: Component, control: Control, source: Source):
        self.component = component
        self.control = control
        self.source = source
        
    def as_dict(self):
        return {
            "component": self.component,
            "control": self.control,
            "source": self.source.as_dict()
        }


class Library():
    def parse_name(self, name):
        # Don't parse if all we have is an ID
        m = re.match(r'^#[a-zA-Z0-9_]+$', name, re.M)
        if m:
            return {"id": name, "name": "", "description": ""}

        # TODO - write tests then handle special global ids #client and #server
        m = re.match(r'(?P<name>[^()]+)(?:(?P<id>\(.*?\))(?P<description>.*)?)?', name, re.M | re.I)
        if m:
            match = m.groupdict()
            
            match["name"] = match["name"].strip()

            if match["name"].startswith("#"):
                match["id"] = match["name"]

            if match["id"]:
                match["id"] = match["id"].strip()
            else:
                if match["name"].endswith("/"):  # Dirty hack
                    id_body = match["name"] + "root"
                else:
                    id_body = match["name"]
                match["id"] = "#" + re.sub('[^a-z0-9_]+', '_', id_body.strip().lower().replace('-', '')).strip('_')

            if match["id"][0] == "(" and match["id"][-1] == ")":
                match["id"] = match["id"][1:-1]

            if not match["id"].startswith("#"):  # Very, very dirty hack
                if match["id"].endswith("/"):  # Dirty hack
                    id_body = match["id"] + "root"
                else:
                    id_body = match["id"]
                match["id"] = "#" + re.sub('[^a-z0-9_]+', '_', id_body.strip().lower().replace('-', '')).strip('_')

            if match["description"]:
                match["description"] = match["description"].strip()
            else:
                match["description"] = ""
            return match
        else:
            raise RuntimeError("Failed to parse ID: {}".format(name))


class ThreatLibrary(Library):
    def __init__(self, threats: Dict[str, Threat] = {}):
        self.threats = threats

    def add_threat(self, name=None, run_id=None):
        data = self.parse_name(name)
        if isinstance(data, str):
            return data
        if not data["id"] in self.threats:
            self.threats[data["id"]] = Threat(data["id"], run_id, data["name"], data["description"])  # TODO: Handle id clash
        return data["id"]

    def load(self, data, run_id=None):
        for id, threat in data["threats"].items():
            if run_id:
                threat["run_id"] = run_id  # Override the run ID if provided
            if id not in self.threats:  # TODO Handle id clash
                self.threats[id] = Threat(id, threat["run_id"], threat["name"], threat["description"])
                
    def save(self, run_id=None):
        data = {"threats": {}}
        for id, threat in self.threats.items():
            if not threat.run_id:
                continue
            if not run_id or threat.run_id == run_id:
                data["threats"][id] = threat.as_dict()
        return data

        
class ControlLibrary(Library):
    def __init__(self, controls: Dict[str, Control] = {}):
        self.controls = controls

    def add_control(self, name=None, run_id=None):
        data = self.parse_name(name)
        if isinstance(data, str):
            return data
        if not data["id"] in self.controls:
            self.controls[data["id"]] = Control(data["id"], run_id, data["name"], data["description"])
        return data["id"]

    def load(self, data, run_id=None):
        for id, control in data["controls"].items():
            if run_id:
                control["run_id"] = run_id  # Override the run ID if provided
            if id not in self.controls:  # TODO Handle id clash
                self.controls[id] = Control(id, control["run_id"], control["name"], control["description"])
    
    def save(self, run_id=None):
        data = {"controls": {}}
        for id, control in self.controls.items():
            if not control.run_id:
                continue
            if not run_id or control.run_id == run_id:
                data["controls"][id] = control.as_dict()
        return data


class ComponentLibrary(Library):
    def __init__(self, components: Dict[str, Component] = {}):
        self.components = components

    def add_component(self, name=None, run_id=None):
        data = self.parse_name(name)
        if isinstance(data, str):
            return data

        if not data["id"] in self.components:
            self.components[data["id"]] = Component(data["id"], run_id, data["name"], data["description"], [])

        path = data["name"].split(":")[0:-1]  # Ignore the last one as that's the component itself
        if path not in self.components[data["id"]].paths:
            self.components[data["id"]].paths.append(path)
        return data["id"]

    def load(self, data, run_id=None):
        for id, component in data["components"].items():
            if run_id:
                component["run_id"] = run_id  # Override the run ID if provided
            if id not in self.components:  # TODO Handle id clash
                self.components[id] = Component(id, component["run_id"], component["name"], component["description"], component["paths"])
                
    def save(self, run_id=None):
        data = {"components": {}}
        for id, component in self.components.items():
            if not component.run_id:
                continue
            if not run_id or component.run_id == run_id:
                data["components"][id] = component.as_dict()
        return data
                

class ThreatModel(Library):
    def __init__(self,
            mitigations: List[Mitigation] = [],
            acceptances: List[Acceptance] = [],
            transfers: List[Transfer] = [],
            exposures: List[Exposure] = [],
            connections: List[Connection] = [],
            reviews: List[Review] = [],
            tests: List[Test] = [],
            run_id: str = ""):
        
        self.mitigations = mitigations
        self.acceptances = acceptances
        self.transfers = transfers
        self.exposures = exposures
        self.connections = connections
        self.reviews = reviews
        self.tests = tests
        self.run_id = run_id
        
        self.threat_library = None
        self.control_library = None
        self.component_library = None

    def add_mitigation(self, threat, control, component, source):
        self.mitigations.append(Mitigation(
            self.control_library.add_control(control, self.run_id),
            self.threat_library.add_threat(threat, self.run_id),
            self.component_library.add_component(component, self.run_id),
            Source(**source)
        ))

    def add_acceptance(self, threat, component, details, source):
        self.acceptances.append(Acceptance(
            self.threat_library.add_threat(threat, self.run_id),
            self.component_library.add_component(component, self.run_id),
            details,
            Source(**source)
        ))

    def add_transfer(self, threat, source_component, destination_component, details, source):
        self.transfers.append(Transfer(
            self.threat_library.add_threat(threat, self.run_id),
            self.component_library.add_component(source_component, self.run_id),
            self.component_library.add_component(destination_component, self.run_id),
            details,
            Source(**source)
        ))

    def add_exposure(self, threat, component, details, source):
        self.exposures.append(Exposure(
            self.threat_library.add_threat(threat, self.run_id),
            self.component_library.add_component(component, self.run_id),
            details,
            Source(**source)
        ))

    def add_connection(self, source_component, destination_component, direction, details, source):
        self.connections.append(Connection(
            self.component_library.add_component(source_component, self.run_id),
            self.component_library.add_component(destination_component, self.run_id),
            direction,
            details,
            Source(**source))
        )

    def add_review(self, component, details, source):
        self.reviews.append(Review(
            self.component_library.add_component(component, self.run_id),
            details,
            Source(**source)
        ))

    def add_test(self, component, control, source):
        self.tests.append(Test(
            self.component_library.add_component(component, self.run_id),
            self.control_library.add_control(control, self.run_id),
            Source(**source)
        ))

    def load(self, data):
        for mitigation in data["mitigations"]:
            self.add_mitigation(**mitigation)
        for exposure in data["exposures"]:
            self.add_exposure(**exposure)
        for transfer in data["transfers"]:
            self.add_transfer(**transfer)
        for acceptance in data["acceptances"]:
            self.add_acceptance(**acceptance)
        for connection in data["connections"]:
            self.add_connection(**connection)
        for review in data["reviews"]:
            self.add_review(**review)
        for test in data["tests"]:
            self.add_test(**test)
            
    def save(self):
        return {
            "mitigations": [x.as_dict() for x in self.mitigations],
            "exposures": [x.as_dict() for x in self.exposures],
            "transfers": [x.as_dict() for x in self.transfers],
            "acceptances": [x.as_dict() for x in self.acceptances],
            "connections": [x.as_dict() for x in self.connections],
            "reviews": [x.as_dict() for x in self.reviews],
            "tests": [x.as_dict() for x in self.tests],
            "run_id": self.run_id
        }

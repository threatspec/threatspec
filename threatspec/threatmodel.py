from pprint import pprint
from dataclasses import dataclass, asdict, field, make_dataclass
from typing import List, Dict, ClassVar
import uuid, re

@dataclass
class Source():
    annotation: str
    code: str
    filename: str
    line: int

@dataclass
class Threat():
    id: str
    run_id: str
    name: str
    description: str = ""

@dataclass
class Control():
    id: str
    run_id: str
    name: str
    description: str = ""

@dataclass
class Component():
    id: str
    run_id: str
    name: str
    description: str = ""
    paths: List[str] = field(default_factory=list)

@dataclass
class Mitigation():
    control: Control
    threat: Threat
    component: Component
    source: Source

@dataclass
class Acceptance():
    threat: Threat
    component: Component
    details: str
    source: Source

@dataclass
class Transfer():
    threat: Threat
    source_component: Component
    destination_component: Component
    details: str
    source: Source

@dataclass
class Exposure():
    threat: Threat
    component: Component
    details: str
    source: Source

@dataclass
class Connection():
    source_component: Component
    destination_component: Component
    direction: str
    details: str
    source: Source

@dataclass
class Review():
    component: Component
    details: str
    source: Source

@dataclass
class Test():
    component: Component
    control: Control
    source: Source

@dataclass
class Library():
    def parse(self, name):
        # Don't parse if all we have is an ID
        m = re.match(r'^#[a-z0-9_]+$', name, re.M)
        if m:
            return name

        # TODO - write tests then handle special global ids #client and #server
        m = re.match(r'(?P<name>[^()]+)(?:(?P<id>\(.*?\))(?P<description>.*)?)?', name, re.M | re.I)
        if m:
            match = m.groupdict()

            if match["name"].startswith("#"):
                match["id"] = match["name"]

            if not match["id"]:
                if match["name"].endswith("/"): # Dirty hack
                    id_body = match["name"]+"root"
                else:
                    id_body = match["name"]
                match["id"] = "#" + re.sub('[^a-z0-9_]+', '_', id_body.strip().lower().replace('-','')).strip('_')

            if match["id"][0] == "(" and match["id"][-1] == ")":
                match["id"] = match["id"][1:-1]

            if not match["id"].startswith("#"): # Very, very dirty hack
                if match["id"].endswith("/"): # Dirty hack
                    id_body = match["id"]+"root"
                else:
                    id_body = match["id"]
                match["id"] = "#" + re.sub('[^a-z0-9_]+', '_', id_body.strip().lower().replace('-','')).strip('_')

            if not match["description"]:
                match["description"] = ""
            return match
        else:
            raise RuntimeError("Failed to parse ID: {}".format(name))

@dataclass
class ThreatLibrary(Library):
    threats: Dict[str, Threat] = field(default_factory=dict)

    def add_threat(self, name=None, run_id=None):
        data = self.parse(name)
        if isinstance(data, str):
            return data
        if not data["id"] in self.threats:
            self.threats[data["id"]] = Threat(data["id"], run_id, data["name"], data["description"]) # TODO: Handle id clash
        return data["id"]

    def load(self, data):
        for id, threat in data["threats"].items():
            if id not in self.threats: # TODO Handle id clash
                self.threats[id] = Threat(id, threat["run_id"], threat["name"], threat["description"])
                
    def save(self, run_id=None):
        if not run_id:
            return asdict(self)
            
        data = {"threats":{}}
        for id, threat in self.threats.items():
            if not threat.run_id:
                continue
            if threat.run_id == run_id:
                data["threats"][id] = asdict(threat)
        return data
        
@dataclass
class ControlLibrary(Library):
    controls: Dict[str, Control] = field(default_factory=dict)

    def add_control(self, name=None, run_id=None):
        data = self.parse(name)
        if isinstance(data, str):
            return data
        if not data["id"] in self.controls:
            self.controls[data["id"]] = Control(data["id"], run_id, data["name"], data["description"])
        return data["id"]

    def load(self, data):
        for id, control in data["controls"].items():
            if id not in self.controls: # TODO Handle id clash
                self.controls[id] = Control(id, control["run_id"], control["name"], control["description"])
    
    def save(self, run_id=None):
        if not run_id:
            return asdict(self)
        
        data = {"controls":{}}
        for id, control in self.controls.items():
            if not control.run_id:
                continue
            if control.run_id == run_id:
                data["controls"][id] = asdict(control)
        return data

@dataclass
class ComponentLibrary(Library):
    components: Dict[str, Component] = field(default_factory=dict)

    def add_component(self, name=None, run_id=None):
        data = self.parse(name)
        if isinstance(data, str):
            return data

        path = data["name"].split(":")[0:-1] # Ignore the last one as that's the component itself

        if not data["id"] in self.components:
            self.components[data["id"]] = Component(data["id"], run_id, data["name"], data["description"])
        elif path not in self.components[data["id"]].paths:
            self.components[data["id"]].paths.append(path)
        return data["id"]

    def load(self, data):
        for id, component in data["components"].items():
            if id not in self.components: # TODO Handle id clash
                self.components[id] = Component(id, component["run_id"], component["name"], component["description"], component["paths"])
                
    def save(self, run_id=None):
        if not run_id:
            return asdict(self)
        
        data = {"components":{}}
        for id, component in self.components.items():
            if not component.run_id:
                continue
            if component.run_id == run_id:
                data["components"][id] = asdict(component)
        return data
                

@dataclass
class ThreatModel(Library):
    mitigations: List[Mitigation] = field(default_factory=list)
    acceptances: List[Acceptance] = field(default_factory=list)
    transfers: List[Transfer] = field(default_factory=list)
    exposures: List[Exposure] = field(default_factory=list)
    connections: List[Connection] = field(default_factory=list)
    reviews: List[Review] = field(default_factory=list)
    tests: List[Test] = field(default_factory=list)
    
    run_id: str = field(default_factory=str)

    threat_library: ClassVar
    control_library: ClassVar
    component_library: ClassVar

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
            Source(**source)
            ))

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
        return asdict(self)
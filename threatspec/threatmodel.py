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
    def __init__(self, id: str, run_id: str, name: str, description: str, custom: dict):
        self.id = id
        self.run_id = run_id
        self.name = name
        self.description = description
        self.custom = custom
        
    def update(self, run_id: str, name: str, description: str, custom: dict):
        if run_id:
            self.run_id = run_id
        if name:
            self.name = name
        if description:
            self.description = description
        if custom:
            self.custom.update(custom)

    def as_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "name": self.name,
            "description": self.description,
            "custom": self.custom
        }


class Control():
    def __init__(self, id: str, run_id: str, name: str, description: str, custom: dict):
        self.id = id
        self.run_id = run_id
        self.name = name
        self.description = description
        self.custom = custom

    def update(self, run_id: str, name: str, description: str, custom: dict):
        if run_id:
            self.run_id = run_id
        if name:
            self.name = name
        if description:
            self.description = description
        if custom:
            self.custom.update(custom)
        
    def as_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "name": self.name,
            "description": self.description,
            "custom": self.custom
        }


class Component():
    def __init__(self, id: str, run_id: str, name: str, description: str, paths: List[str], custom: dict):
        self.id = id
        self.run_id = run_id
        self.name = name
        self.description = description
        self.paths = paths
        self.custom = custom
        
    def update(self, run_id: str, name: str, description: str, paths: List[str], custom: dict):
        if run_id:
            self.run_id = run_id
        if name:
            self.name = name
        if description:
            self.description = description
        if paths:
            self.paths = paths
        if custom:
            self.custom.update(custom)
            
    def as_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "name": self.name,
            "description": self.description,
            "paths": self.paths,
            "custom": self.custom
        }


class Mitigation():
    def __init__(self, control: Control, threat: Threat, component: Component, description: str, custom: dict, source: Source):
        self.control = control
        self.threat = threat
        self.component = component
        self.description = description
        self.custom = custom
        self.source = source
        
    def as_dict(self):
        return {
            "control": self.control,
            "threat": self.threat,
            "component": self.component,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Acceptance():
    def __init__(self, threat: Threat, component: Component, details: str, description: str, custom: dict, source: Source):
        self.threat = threat
        self.component = component
        self.details = details
        self.description = description
        self.custom = custom
        self.source = source
        
    def as_dict(self):
        return {
            "threat": self.threat,
            "component": self.component,
            "details": self.details,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Transfer():
    def __init__(self, threat: Threat, source_component: Component, destination_component: Component, details: str, description: str, custom: dict, source: Source):
        self.threat = threat
        self.source_component = source_component
        self.destination_component = destination_component
        self.details = details
        self.description = description
        self.custom = custom
        self.source = source
        
    def as_dict(self):
        return {
            "threat": self.threat,
            "source_component": self.source_component,
            "destination_component": self.destination_component,
            "details": self.details,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Exposure():
    def __init__(self, threat: Threat, component: Component, details: str, description: str, custom: dict, source: Source):
        self.threat = threat
        self.component = component
        self.details = details
        self.description = description
        self.custom = custom
        self.source = source
    
    def as_dict(self):
        return {
            "threat": self.threat,
            "component": self.component,
            "details": self.details,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Connection():
    def __init__(self, source_component: Component, destination_component: Component, direction: str, details: str, description: str, custom: dict, source: Source):
        self.source_component = source_component
        self.destination_component = destination_component
        self.direction = direction
        self.details = details
        self.description = description
        self.custom = custom
        self.source = source
        
    def as_dict(self):
        return {
            "source_component": self.source_component,
            "destination_component": self.destination_component,
            "direction": self.direction,
            "details": self.details,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Review():
    def __init__(self, component: Component, details: str, description: str, custom: dict, source: Source):
        self.component = component
        self.details = details
        self.description = description
        self.custom = custom
        self.source = source

    def as_dict(self):
        return {
            "component": self.component,
            "details": self.details,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Test():
    def __init__(self, component: Component, control: Control, description: str, custom: dict, source: Source):
        self.component = component
        self.control = control
        self.description = description
        self.custom = custom
        self.source = source
        
    def as_dict(self):
        return {
            "component": self.component,
            "control": self.control,
            "description": self.description,
            "custom": self.custom,
            "source": self.source.as_dict()
        }


class Library():
    # TODO - move this into parser.py
    def parse_name(self, data):
        name = ""
        id = ""
        
        # Don't parse if all we have is an ID
        m = re.match(r'^#[a-zA-Z0-9_]+$', data, re.M)
        if m:
            return ("", data)

        # TODO - write tests then handle special global ids #client and #server
        m = re.match(r'(?P<name>[^()]+)(?:(?P<id>\(.*?\)))?', data, re.M | re.I)
        if m:
            match = m.groupdict()
            
            name = match["name"].strip()

            if name.startswith("#"):
                id = match["name"]

            if match["id"]:
                id = match["id"].strip()
            else:
                if name.endswith("/"):  # Dirty hack
                    id_body = name + "root"
                else:
                    id_body = name
                id = "#" + re.sub('[^a-z0-9_]+', '_', id_body.strip().lower().replace('-', '')).strip('_')

            if id[0] == "(" and id[-1] == ")":
                id = id[1:-1]

            if not id.startswith("#"):  # Very, very dirty hack
                if id.endswith("/"):  # Dirty hack
                    id_body = id + "root"
                else:
                    id_body = id
                id = "#" + re.sub('[^a-z0-9_]+', '_', id_body.strip().lower().replace('-', '')).strip('_')

            return (name, id)
        else:
            raise RuntimeError("Failed to parse ID: {}".format(data))


class ThreatLibrary(Library):
    def __init__(self, threats: Dict[str, Threat] = {}):
        self.threats = threats

    def add_threat(self, data, run_id=None):
        if isinstance(data, dict):
            threat = data.pop("threat")
            description = data.pop("description", "")
        else:
            threat = data
            description = ""
            data = {}
        (name, threat_id) = self.parse_name(threat)
        if threat_id in self.threats:
            if threat_id != name:
                # We haven't been given a reference to an existing threat
                self.threats[threat_id].update(run_id, name, description, data)
        else:
            self.threats[threat_id] = Threat(threat_id, run_id, name, description, data)
        return threat_id

    def load(self, data, run_id=None):
        for id, threat in data["threats"].items():
            if id not in self.threats:
                if not run_id:
                    run_id = threat.pop("run_id", "")
                name = threat.pop("name")
                description = threat.pop("description", "")
                if "custom" in threat:
                    custom = threat["custom"]
                else:
                    custom = threat
                self.threats[id] = Threat(id, run_id, name, description, custom)
                
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

    def add_control(self, data, run_id=None):
        if isinstance(data, dict):
            control = data.pop("control")
            description = data.pop("description", "")
        else:
            control = data
            description = ""
            data = {}
        (name, control_id) = self.parse_name(control)
        if control_id in self.controls:
            if control_id != name:
                # We haven't just been given a reference to an existing control
                self.controls[control_id].update(run_id, name, description, data)
        else:
            self.controls[control_id] = Control(control_id, run_id, name, description, data)
        return control_id

    def load(self, data, run_id=None):
        for id, control in data["controls"].items():
            if id not in self.controls:
                if not run_id:
                    run_id = control.pop("run_id", "")
                name = control.pop("name")
                description = control.pop("description", "")
                if "custom" in control:
                    custom = control["custom"]
                else:
                    custom = control
                self.controls[id] = Control(id, run_id, name, description, custom)
    
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

    def add_component(self, data, run_id=None):
        if isinstance(data, dict):
            component = data.pop("component")
            description = data.pop("description", "")
            paths = data.pop("paths", [])
        else:
            component = data
            description = ""
            paths = []
            data = {}
        (name, component_id) = self.parse_name(component)
        if component_id in self.components:
            if component_id != name:
                # We haven't just been given a reference to an existing component
                self.components[component_id].update(run_id, name, description, paths, data)
        else:
            self.components[component_id] = Component(component_id, run_id, name, description, paths, data)

        path = name.split(":")[0:-1]  # Ignore the last one as that's the component itself
        if path not in self.components[component_id].paths:
            self.components[component_id].paths.append(path)
        return component_id

    def load(self, data, run_id=None):
        for id, component in data["components"].items():
            if id not in self.components:
                if not run_id:
                    run_id = component.pop("run_id", "")
                name = component.pop("name")
                description = component.pop("description", "")
                paths = component.pop("paths", [])
                if "custom" in component:
                    custom = component["custom"]
                else:
                    custom = component
                self.components[id] = Component(id, run_id, name, description, paths, custom)
                
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

    def add_mitigation(self, data, source):
        control = self.control_library.add_control(data.pop("control"), self.run_id)
        threat = self.threat_library.add_threat(data.pop("threat"), self.run_id)
        component = self.component_library.add_component(data.pop("component"), self.run_id)
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.mitigations.append(Mitigation(control, threat, component, description, custom, Source(**source)))

    def add_acceptance(self, data, source):
        threat = self.threat_library.add_threat(data.pop("threat"), self.run_id)
        component = self.component_library.add_component(data.pop("component"), self.run_id)
        details = data.pop("details")
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.acceptances.append(Acceptance(threat, component, details, description, custom, Source(**source)))

    def add_transfer(self, data, source):
        threat = self.threat_library.add_threat(data.pop("threat"), self.run_id)
        source_component = self.component_library.add_component(data.pop("source_component"), self.run_id)
        destination_component = self.component_library.add_component(data.pop("destination_component"), self.run_id)
        details = data.pop("details")
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.transfers.append(Transfer(threat, source_component, destination_component, details, description, custom, Source(**source)))

    def add_exposure(self, data, source):
        threat = self.threat_library.add_threat(data.pop("threat"), self.run_id)
        component = self.component_library.add_component(data.pop("component"), self.run_id)
        details = data.pop("details")
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.exposures.append(Exposure(threat, component, details, description, custom, Source(**source)))

    def add_connection(self, data, source):
        source_component = self.component_library.add_component(data.pop("source_component"), self.run_id)
        destination_component = self.component_library.add_component(data.pop("destination_component"), self.run_id)
        direction = data.pop("direction")
        details = data.pop("details")
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.connections.append(Connection(source_component, destination_component, direction, details, description, custom, Source(**source)))

    def add_review(self, data, source):
        component = self.component_library.add_component(data.pop("component"), self.run_id)
        details = data.pop("details")
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.reviews.append(Review(component, details, description, custom, Source(**source)))

    def add_test(self, data, source):
        component = self.component_library.add_component(data.pop("component"), self.run_id)
        control = self.control_library.add_control(data.pop("control"), self.run_id)
        description = data.pop("description", "")
        if "custom" in data:
            custom = data["custom"]
        else:
            custom = data
        self.tests.append(Test(component, control, description, custom, Source(**source)))

    def add_threat(self, data, source):
        self.threat_library.add_threat(data, self.run_id)
        
    def add_control(self, data, source):
        self.control_library.add_control(data, self.run_id)
        
    def add_component(self, data, source):
        self.component_library.add_component(data, source)
        
    def load(self, data):
        for mitigation in data["mitigations"]:
            self.add_mitigation(mitigation, mitigation.pop("source"))
        for exposure in data["exposures"]:
            self.add_exposure(exposure, exposure.pop("source"))
        for transfer in data["transfers"]:
            self.add_transfer(transfer, transfer.pop("source"))
        for acceptance in data["acceptances"]:
            self.add_acceptance(acceptance, acceptance.pop("source"))
        for connection in data["connections"]:
            self.add_connection(connection, connection.pop("source"))
        for review in data["reviews"]:
            self.add_review(review, review.pop("source"))
        for test in data["tests"]:
            self.add_test(test, test.pop("source"))
            
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

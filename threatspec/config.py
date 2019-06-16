from dataclasses import dataclass, field
from typing import List, Dict, Any
from threatspec import data

@dataclass
class Project:
    name: str = field(default_factory=str)
    description: str = field(default_factory=str)

# TODO: Work out if this is better as a dataclass anyway
class Path:
    def __init__(self, obj):
        self.path = ""
        self.ignore = ""

        if isinstance(obj, str):
            self.path = obj
        elif isinstance(obj, dict):
            if "path" not in obj:
                raise ValueError("path key missing from path")
            self.path = obj["path"]
            if "ignore" in obj:
                if isinstance(obj["ignore"], str):
                    self.ignore = [obj["ignore"]]
                elif isinstance(obj["ignore"], list):
                    self.ignore = obj["ignore"]
                else:
                    raise TypeError("ignore must be a string or list")

@dataclass
class Config:
    project: Project = field(default_factory=Project)
    paths: List[Path] = field(default_factory=list)

    def load(self, data):
        self.project = Project(data["project"]["name"], data["project"]["description"])
        for path in data["paths"]:
            self.paths.append(Path(path))
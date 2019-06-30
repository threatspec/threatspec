class Project():
    def __init__(self, name: str = "", description: str = ""):
        self.name = name
        self.description = description


class Path():
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


class Config():
    def __init__(self):
        self.project = None
        self.paths = []

    def load(self, data):
        self.project = Project(data["project"]["name"], data["project"]["description"])
        for path in data["paths"]:
            self.paths.append(Path(path))

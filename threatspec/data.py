import pkg_resources
import os
import json
import yaml
import shutil
import glob
import jsonschema


def cwd():
    return os.getcwd()


def abs_path(*paths):
    return os.path.abspath(os.path.join(*paths))

    
def glob_to_root(path):
    if "*" in path:
        return os.path.dirname(path.split("*")[0])
    return os.path.dirname(path)


def recurse_path(path):
    if os.path.isfile(path):
        return [path]
    else:
        if "*" in path:
            return glob.iglob(path)
        else:
            return glob.iglob(os.path.join(path, "**/*"), recursive=True)


def blacklisted_path(path):
    blacklisted_files = [
        "threatspec.yaml",
        "ThreatModel*"
    ]
    blacklisted_dirs = [
        "threatmodel",
    ]
    
    if os.path.isfile(path) and os.path.basename(path) in blacklisted_files:
        return True
    
    if os.path.isdir(path) and os.path.split(os.path.dirname(path))[-1] in blacklisted_dirs:
        return True
        
    return False
    
    
def path_ignored(path, ignore):
    for i in ignore:
        if i in path:
            return True
    return False


def is_threatspec_path(path):
    return os.path.isfile(os.path.join(path, "threatspec.yaml"))


def create_directories(paths):
    for path in paths:
        try:
            os.mkdir(path)
        except FileExistsError:
            pass


def write_json_pretty(data, *path):
    path = os.path.join(*path)
    with open(path, 'w') as fh:
        json.dump(data, fh, indent=2)


def read_json(*path):
    path = os.path.join(*path)
    with open(path) as fh:
        return json.load(fh)


def write_file(data, *path):
    path = os.path.join(*path)
    with open(path, 'w') as fh:
        fh.write(data)


def read_yaml(*path):
    path = os.path.join(*path)
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.SafeLoader)


def write_yaml(data, *path):
    path = os.path.join(*path)
    with open(path, 'w') as fh:
        fh.write(yaml.dump(data))


def validate_yaml_file(file_path, schema_file):
    if not os.path.isfile(file_path):
        return (True, None)
    schema_path = resolve_pkg_file(schema_file)
    try:
        jsonschema.validate(read_yaml(file_path), read_yaml(schema_path))
    except jsonschema.exceptions.ValidationError as e:
        return (False, str(e))
    return (True, None)

    
def resolve_pkg_file(*path):
    return pkg_resources.resource_filename("threatspec", os.path.join(*path))

    
def copy_pkg_file(src, dest):
    if os.path.isfile(dest):
        raise FileExistsError("File {} already exists.".format(dest))
    source = resolve_pkg_file(src)
    shutil.copyfile(source, dest)

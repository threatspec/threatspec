import pytest
from threatspec import threatmodel

###############################################################################
# Basic objects
###############################################################################

def test_source_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    assert source.as_dict() == {"annotation": "annotation", "code": "code", "filename": "filename", "line": 0}
    
def test_threat_dict():
    threat = threatmodel.Threat("#id", "run_id", "name", "a description")
    assert threat.as_dict() == {"id": "#id", "run_id": "run_id", "name": "name", "description": "a description"}
    
def test_control_dict():
    control = threatmodel.Control("#id", "run_id", "name", "a description")
    assert control.as_dict() == {"id": "#id", "run_id": "run_id", "name": "name", "description": "a description"}
    

def test_component_dict():
    component = threatmodel.Component("#id", "run_id", "name", "a description", ["path1", "path2"])
    assert component.as_dict() == {"id": "#id", "run_id": "run_id", "name": "name", "description": "a description", "paths": ["path1", "path2"]}


def test_mitigation_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    mitigation = threatmodel.Mitigation("#control", "#threat", "#component", source)
    
    assert mitigation.as_dict() == {
        "control": "#control",
        "threat": "#threat",
        "component": "#component",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_acceptance_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    acceptance = threatmodel.Acceptance("#threat", "#component", "details", source)
    
    assert acceptance.as_dict() == {
        "threat": "#threat",
        "component": "#component",
        "details": "details",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_transfer_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    transfer = threatmodel.Transfer("#threat", "#source_component", "#destination_component", "details", source)
    
    assert transfer.as_dict() == {
        "threat": "#threat",
        "source_component": "#source_component",
        "destination_component": "#destination_component",
        "details": "details",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_exposure_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    exposure = threatmodel.Exposure("#threat", "#component", "details", source)
    
    assert exposure.as_dict() == {
        "threat": "#threat",
        "component": "#component",
        "details": "details",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }
    

def test_connection_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    connection = threatmodel.Connection("#source_component", "#destination_component", "direction", "details", source)
    
    assert connection.as_dict() == {
        "source_component": "#source_component",
        "destination_component": "#destination_component",
        "direction": "direction",
        "details": "details",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_review_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    review = threatmodel.Review("#component", "details", source)
    
    assert review.as_dict() == {
        "component": "#component",
        "details": "details",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }
    
    
def test_test_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    test = threatmodel.Test("#component", "#control", source)
    
    assert test.as_dict() == {
        "component": "#component",
        "control": "#control",
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }
    

###############################################################################
# Library name parsing
###############################################################################

    
def test_threatmodel_library_parse_name():
    t = threatmodel.Library()

    assert t.parse_name("#abc") == {"id": "#abc", "name": "", "description": ""}
    assert t.parse_name("#ABC") == {"id": "#ABC", "name": "", "description": ""}

    
def test_threatmodel_library_parse_threat_name():
    t = threatmodel.ThreatLibrary()
    
    assert t.parse_name("A Threat") == {"id": "#a_threat", "name": "A Threat", "description": ""}

    
def test_threatmodel_library_parse_control_name():
    t = threatmodel.ControlLibrary()
    
    assert t.parse_name("A Control") == {"id": "#a_control", "name": "A Control", "description": ""}

    
def test_threatmodel_library_parse_component_name():
    t = threatmodel.ComponentLibrary()
    
    assert t.parse_name("Path:To:Component") == {"id": "#path_to_component", "name": "Path:To:Component", "description": ""}
    assert t.parse_name("Path:To:Component (#MYID)") == {"id": "#MYID", "name": "Path:To:Component", "description": ""}
    assert t.parse_name("Path:To:Component (An:Other:Component)") == {"id": "#an_other_component", "name": "Path:To:Component", "description": ""}
    assert t.parse_name("Component (#component) A longer description") == {"id": "#component", "name": "Component", "description": "A longer description"}
    
    
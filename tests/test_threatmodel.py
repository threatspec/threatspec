import pytest
from threatspec import threatmodel

###############################################################################
# Basic objects
###############################################################################

def test_source_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    assert source.as_dict() == {"annotation": "annotation", "code": "code", "filename": "filename", "line": 0}
    
def test_threat_dict():
    threat = threatmodel.Threat("#id", "run_id", "name", "description", {"impact": "high"})
    assert threat.as_dict() == {"id": "#id", "run_id": "run_id", "name": "name", "description": "description", "custom": {"impact": "high"}}
    
def test_control_dict():
    control = threatmodel.Control("#id", "run_id", "name", "description", {"impact": "high"})
    assert control.as_dict() == {"id": "#id", "run_id": "run_id", "name": "name", "description": "description", "custom": {"impact": "high"}}
    
def test_component_dict():
    component = threatmodel.Component("#id", "run_id", "name", "description", ["path1","path2"], {"impact": "high"})
    assert component.as_dict() == {"id": "#id", "run_id": "run_id", "name": "name", "description": "description", "paths": ["path1", "path2"], "custom": {"impact": "high"}}


def test_mitigation_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    mitigation = threatmodel.Mitigation("#control", "#threat", "#component", "description", {"impact": "high"}, source)
    
    assert mitigation.as_dict() == {
        "control": "#control",
        "threat": "#threat",
        "component": "#component",
        "description": "description",
        "custom": { "impact": "high" },
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_acceptance_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    acceptance = threatmodel.Acceptance("#threat", "#component", "details", "description", {"impact": "high"}, source)
    
    assert acceptance.as_dict() == {
        "threat": "#threat",
        "component": "#component",
        "details": "details",
        "description": "description",
        "custom": { "impact": "high" },
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_transfer_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    transfer = threatmodel.Transfer("#threat", "#source_component", "#destination_component", "details", "description", {"impact": "high"}, source)
    
    assert transfer.as_dict() == {
        "threat": "#threat",
        "source_component": "#source_component",
        "destination_component": "#destination_component",
        "details": "details",
        "description": "description",
        "custom": { "impact": "high" },
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_exposure_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    exposure = threatmodel.Exposure("#threat", "#component", "details", "description", {"impact": "high"}, source)
    
    assert exposure.as_dict() == {
        "threat": "#threat",
        "component": "#component",
        "details": "details",
        "description": "description",
        "custom": { "impact": "high" },
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }
    

def test_connection_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    connection = threatmodel.Connection("#source_component", "#destination_component", "direction", "details", "description", {"impact": "high"}, source)
    
    assert connection.as_dict() == {
        "source_component": "#source_component",
        "destination_component": "#destination_component",
        "direction": "direction",
        "details": "details",
        "description": "description",
        "custom": { "impact": "high" },
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }


def test_review_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    review = threatmodel.Review("#component", "details", "description", {"impact": "high"}, source)
    
    assert review.as_dict() == {
        "component": "#component",
        "details": "details",
        "description": "description",
        "custom": { "impact": "high" },
        "source": {
            "annotation": "annotation",
            "code": "code",
            "filename": "filename",
            "line": 0
        }
    }
    
    
def test_test_dict():
    source = threatmodel.Source("annotation", "code", "filename", 0)
    test = threatmodel.Test("#component", "#control", "description", {"impact": "high"}, source)
    
    assert test.as_dict() == {
        "component": "#component",
        "control": "#control",
        "description": "description",
        "custom": { "impact": "high" },
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

    
def test_threatmodel_library_parse_name_id():
    t = threatmodel.Library()

    assert t.parse_name("#abc") == ("", "#abc")
    assert t.parse_name("#ABC") == ("", "#ABC")

    
def test_threatmodel_library_parse_name_threat():
    t = threatmodel.ThreatLibrary()
    
    assert t.parse_name("A Threat") == ("A Threat", "#a_threat")

    
def test_threatmodel_library_parse_name_control():
    t = threatmodel.ControlLibrary()
    
    assert t.parse_name("A Control") == ("A Control", "#a_control")

    
def test_threatmodel_library_parse_component_name():
    t = threatmodel.ComponentLibrary()
    
    assert t.parse_name("Path:To:Component") == ("Path:To:Component", "#path_to_component")
    assert t.parse_name("Path:To:Component (#MYID)") == ("Path:To:Component", "#MYID")
    assert t.parse_name("Path:To:Component (An:Other:Component)") == ("Path:To:Component", "#an_other_component")

    
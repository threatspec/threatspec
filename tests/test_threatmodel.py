import pytest
from threatspec import threatmodel

def test_parse_component_id_case():
    t = threatmodel.ComponentLibrary()
    
    assert t.parse("#abc") == {"id": "#abc", "name": "", "description": ""}
    assert t.parse("#ABC") == {"id": "#ABC", "name": "", "description": ""}
    assert t.parse("Path:To:Component") == {"id": "#path_to_component", "name": "Path:To:Component", "description": ""}
    assert t.parse("Path:To:Component (#MYID)") == {"id": "#MYID", "name": "Path:To:Component", "description": ""}
    assert t.parse("Path:To:Component (An:Other:Component)") == {"id": "#an_other_component", "name": "Path:To:Component", "description": ""}
    assert t.parse("Component (#component) A longer description") == {"id": "#component", "name": "Component", "description": "A longer description"}
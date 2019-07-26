import pytest
from threatspec import parser, threatmodel
import yaml

def test_source_file_parser_parse_comments():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)

    comments = [{
            "test": "@mitigates Path:To:Component against a multi word threat with a multi word control",
            "result": {
                "action": "mitigate",
                "component": "Path:To:Component",
                "threat": "a multi word threat",
                "control": "a multi word control"
            }
        }, {
            "test": "@accepts a multi word threat to Path:To:Component with why it has been accepted",
            "result": {
                "action": "accept",
                "threat": "a multi word threat",
                "component": "Path:To:Component",
                "details": "why it has been accepted"
            }
        }, {
            "test": "@transfers a multi word threat from Path:To:Source to Path:To:Destination with why it has been transfered",
            "result": {
                "action": "transfer",
                "threat": "a multi word threat",
                "source_component": "Path:To:Source",
                "destination_component": "Path:To:Destination",
                "details": "why it has been transfered"
            }
        }, {
            "test": "@exposes Path:To:Component to a multi word threat with how it is exposed",
            "result": {
                "action": "expose",
                "threat": "a multi word threat",
                "component": "Path:To:Component",
                "details": "how it is exposed"
            }
        }, {
            "test": "@connects Path:To:Source with Path:To:Destination with details about connection",
            "result": {
                "action": "connect",
                "source_component": "Path:To:Source",
                "destination_component": "Path:To:Destination",
                "direction": "with",
                "details": "details about connection"
            }
        }, {
            "test": "@review Path:To:Component something worth noting",
            "result": {
                "action": "review",
                "component": "Path:To:Component",
                "details": "something worth noting"
            }
        }, {
            "test": "@tests a multi word control for Path:To:Component",
            "result": {
                "action": "test",
                "control": "a multi word control",
                "component": "Path:To:Component"
            }
        }]

    for comment in comments:
        data = p.parse_comment(comment["test"])
        assert len(data) == 1
        data[0].pop("annotation")
        data[0].pop("line")
        assert data[0] == comment["result"]


def test_parse_threat_extended_comment():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)
    
    comment_text = """
@threat A Threat (#threatid):
  description: |
    A multiline
    description
  impact: high
"""
    annotations = p.parse_comment(comment_text)
    assert len(annotations) == 1
    assert annotations[0]["threat"] == "A Threat (#threatid)"
    assert annotations[0]["description"] == "A multiline\ndescription\n"
    assert annotations[0]["impact"] == "high"


def test_parse_control_extended_comment():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)
    
    comment_text = """
@control A Control (#controlid):
  description: |
    A multiline
    description
  cost: high
"""
    annotations = p.parse_comment(comment_text)
    assert len(annotations) == 1
    assert annotations[0]["control"] == "A Control (#controlid)"
    assert annotations[0]["description"] == "A multiline\ndescription\n"
    assert annotations[0]["cost"] == "high"

    
def test_parse_component_extended_comment():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)
    
    comment_text = """
@component Path:To:Component (#componentid):
  description: |
    A multiline
    description
  value: high
"""
    annotations = p.parse_comment(comment_text)
    assert len(annotations) == 1
    assert annotations[0]["component"] == "Path:To:Component (#componentid)"
    assert annotations[0]["description"] == "A multiline\ndescription\n"
    assert annotations[0]["value"] == "high"

def test_yaml_paser():
    t = threatmodel.ThreatModel()
    t.threat_library = threatmodel.ThreatLibrary()
    p = parser.YamlFileParser(t)
    
    yaml_string = """
        key1:
            key11:
                x-threatspec: "@threat A string threat"
            key12:
                x-threatspec:
                    - "@threat Array threat 1"
                    - "@threat Array threat 2"
        key2:
            key21:
                key211:
                    "x-threatspec":
                        "@threat Extended threat 1":
                            description: Extended description 1
                            impact: high
    """
    
    data = yaml.load(yaml_string, Loader=yaml.SafeLoader)
    p.parse_data(data, {}, "path/to/file")
    
    assert len(t.threat_library.threats) == 4
    
    assert "#a_string_threat" in t.threat_library.threats
    assert t.threat_library.threats["#a_string_threat"].name == "A string threat"
    
    assert "#extended_threat_1" in t.threat_library.threats
    assert t.threat_library.threats["#extended_threat_1"].custom["impact"] == "high"
    
    
import pytest
from threatspec import parser, threatmodel
from pprint import pprint


def test_source_file_parser_parse_comments():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)

    comments = [{
            "test": "@mitigates Path:To:Component against a multi word threat with a multi word control",
            "result": {
                "action": "mitigates",
                "component": "Path:To:Component",
                "threat": "a multi word threat",
                "control": "a multi word control"
            }
        }, {
            "test": "@accepts a multi word threat to Path:To:Component with why it has been accepted",
            "result": {
                "action": "accepts",
                "threat": "a multi word threat",
                "component": "Path:To:Component",
                "details": "why it has been accepted"
            }
        }, {
            "test": "@transfers a multi word threat from Path:To:Source to Path:To:Destination with why it has been transfered",
            "result": {
                "action": "transfers",
                "threat": "a multi word threat",
                "source_component": "Path:To:Source",
                "destination_component": "Path:To:Destination",
                "details": "why it has been transfered"
            }
        }, {
            "test": "@exposes Path:To:Component to a multi word threat with how it is exposed",
            "result": {
                "action": "exposes",
                "threat": "a multi word threat",
                "component": "Path:To:Component",
                "details": "how it is exposed"
            }
        }, {
            "test": "@connects Path:To:Source with Path:To:Destination with details about connection",
            "result": {
                "action": "connects",
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
                "action": "tests",
                "control": "a multi word control",
                "component": "Path:To:Component"
            }
        }]

    for comment in comments:
        data = p.parse_comment(comment["test"])
        assert len(data) == 1
        assert data[0] == comment["result"]

"""
def test_parse_comment_line():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)

    c = [{
            "line": "// A normal comment",
            "annotation": "A normal comment",
            "code": ""
        }, {
            "line": "somecode.action(parameter) // An inline comment",
            "annotation": "An inline comment",
            "code": "somecode.action(parameter)"
        }, {
            "line": "# A normal comment",
            "annotation": "A normal comment",
            "code": ""
        }, {
            "line": "somecode.action(parameter) # An inline comment",
            "annotation": "An inline comment",
            "code": "somecode.action(parameter)"
        }]

    for line in lines:
        (annotation, code) = p.parse_comment_line(line["line"])
        assert line["code"] == code
        assert line["annotation"] == annotation

def test_parse_line():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)

    lines = [{
        "line": "somecode.action(parameter) // @mitigates Path:To:Component against Threat with Control",
        "next_line": "other.action(parameter) // @mitigates Path:To:Component2 against Threat2 with Control2",
        "action": "mitigates",
        "threat": "Threat",
        "component": "Path:To:Component",
        "control": "Control",
        "annotation": "@mitigates Path:To:Component against Threat with Control",
        "code": "somecode.action(parameter)",
        "filename": "afile.js",
        "line_no": 66
    }]

    for line in lines:
        (data, source) = p.parse_line(line["line"], line["next_line"], line["filename"], line["line_no"])
        assert data == {
            "action": "mitigates",
            "threat": "Threat",
            "component": "Path:To:Component",
            "control": "Control"
        }
        assert source == {
            "annotation": line["annotation"],
            "code": line["code"],
            "filename": line["filename"],
            "line": line["line_no"]
        }
"""

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

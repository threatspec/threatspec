import pytest
from threatspec import parser, threatmodel
from pprint import pprint

def test_parser_parse_annotation():
    t = threatmodel.ThreatModel()
    p = parser.Parser(t)

    annotations = [{
            "annotation": "@mitigates Path:To:Component against a multi word threat with a multi word control",
            "action": "mitigates",
            "component": "Path:To:Component",
            "threat": "a multi word threat",
            "control": "a multi word control"
        }, {
            "annotation": "@accepts a multi word threat to Path:To:Component with why it has been accepted",
            "action": "accepts",
            "threat": "a multi word threat",
            "component": "Path:To:Component",
            "details": "why it has been accepted"
        }, {
            "annotation": "@transfers a multi word threat from Path:To:Source to Path:To:Destination with why it has been transfered",
            "action": "transfers",
            "threat": "a multi word threat",
            "source_component": "Path:To:Source",
            "destination_component": "Path:To:Destination",
            "details": "why it has been transfered"
        }, {
            "annotation": "@exposes Path:To:Component to a multi word threat with how it is exposed",
            "action": "exposes",
            "threat": "a multi word threat",
            "component": "Path:To:Component",
            "details": "how it is exposed"
        }, {
            "annotation": "@connects Path:To:Source with Path:To:Destination with details about connection",
            "action": "connects",
            "source_component": "Path:To:Source",
            "destination_component": "Path:To:Destination",
            "direction": "with",
            "details": "details about connection"
        }, {
            "annotation": "@review Path:To:Component something worth noting",
            "action": "review",
            "component": "Path:To:Component",
            "details": "something worth noting"
        }, {
            "annotation": "@tests a multi word control for Path:To:Component",
            "action": "tests",
            "control": "a multi word control",
            "component": "Path:To:Component"
        }]

    for annotation in annotations:
        data = p.parse_annotation(annotation.pop("annotation"))
        assert data == annotation


def test_parse_comment_line():
    t = threatmodel.ThreatModel()
    p = parser.SourceFileParser(t)

    lines = [{
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
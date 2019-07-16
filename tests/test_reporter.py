import pytest
from threatspec import threatmodel, reporter

def test_code_function():
    assert reporter.code("a line of code") == "a line of code"
    assert reporter.code("   a line of code") == "a line of code"
    assert reporter.code("  a first line\n    second line") == "a first line\n  second line"
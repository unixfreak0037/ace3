from typing import Type
import pytest

from saq.util.filter import FILTER_TYPE_STRING_SUB, StringEqualsFilter, StringRegexFilter, StringSubFilter, load_filter, parse_filter_spec


@pytest.mark.parametrize("spec, _type, filter_type, filter_value, inverted, ignore_case", [
    ('sub:test', StringSubFilter, FILTER_TYPE_STRING_SUB, "test", False, False),
    ('!sub:test', StringSubFilter, FILTER_TYPE_STRING_SUB, "test", True, False),
    ('sub_i:test', StringSubFilter, FILTER_TYPE_STRING_SUB, "test", False, True),
    ('!sub_i:test', StringSubFilter, FILTER_TYPE_STRING_SUB, "test", True, True),
])
@pytest.mark.unit
def test_parse_filter_spec(spec: str, _type: Type, filter_type: str, filter_value: str, inverted: bool, ignore_case: bool):
    _filter = parse_filter_spec(spec)
    assert isinstance(_filter, _type)
    assert _filter.filter_type == filter_type
    assert _filter.filter_value == filter_value
    _filter.inverted == inverted
    _filter.ignore_case == ignore_case

@pytest.mark.parametrize("spec, expected", [
    ('sub:test', "Filter(sub,test)"),
    ('!sub:test', "Filter(sub,test(inverted))"),
    ('sub_i:test', "Filter(sub,test(ignore_case))"),
    ('!sub_i:test', "Filter(sub,test(inverted)(ignore_case))"),
])
@pytest.mark.unit
def test_to_string(spec: str, expected: str):
    assert str(parse_filter_spec(spec)) == expected

@pytest.mark.unit
def test_load_filters():
    assert isinstance(load_filter('eq', 'test'), StringEqualsFilter)
    assert isinstance(load_filter('sub', 'test'), StringSubFilter)
    assert isinstance(load_filter('re', 'test'), StringRegexFilter)

@pytest.mark.unit
def test_equals_filter():
    _filter = load_filter('eq', 'test')
    assert _filter.matches('test')
    assert not _filter.matches('testing')
    assert not _filter.matches('istesting')
    assert not _filter.matches('Test')

    _filter = load_filter('sub', 'test', ignore_case=True)
    assert _filter.matches('Test')

    with pytest.raises(ValueError):
        _filter.matches(None)

    with pytest.raises(TypeError):
        _filter.matches(1)

@pytest.mark.unit
def test_substring_filter():
    _filter = load_filter('sub', 'test')
    assert _filter.matches('test')
    assert _filter.matches('testing')
    assert _filter.matches('istesting')
    assert not _filter.matches('Test')

    _filter = load_filter('sub', 'test', ignore_case=True)
    assert _filter.matches('Test')

    with pytest.raises(ValueError):
        _filter.matches(None)

    with pytest.raises(TypeError):
        _filter.matches(1)

@pytest.mark.unit
def test_regex_filter():
    _filter = load_filter('re', '^test')
    assert _filter.matches('test')
    assert not _filter.matches('istesting')
    assert not _filter.matches('Test')
    
    _filter = load_filter('re', 'test', ignore_case=True)
    assert _filter.matches('Test')

    with pytest.raises(ValueError):
        _filter.matches(None)

    with pytest.raises(TypeError):
        _filter.matches(1)
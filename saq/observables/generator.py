from datetime import datetime
import logging
import sys
from typing import Optional, Type, Union

from saq.analysis.observable import Observable
from saq.analysis.serialize.observable_serializer import KEY_TYPE
from saq.observables.base import DefaultObservable, ObservableValueError

OBSERVABLE_TYPE_MAPPING: dict[str, Type[Observable]] = {}

def map_observable_type(_type: str, cls: Type[Observable]):
    # not allowed to remap an existing observable
    if _type in OBSERVABLE_TYPE_MAPPING:
        raise RuntimeError(f"ERROR: remapping observable type {_type} from {OBSERVABLE_TYPE_MAPPING[_type]} to {cls}")

    OBSERVABLE_TYPE_MAPPING[_type] = cls

def create_observable(o_type: str, o_value: str, o_time: Union[str, datetime, None]=None, sort_order: int=100, volatile: bool=False) -> Optional[Observable]:
    """This creates a new Observable instance with the given parameters. Returns None if the parameters are invalid for th given type."""

    o_class = None

    try:
        # use the lookup table to find the class for the given type
        o_class = OBSERVABLE_TYPE_MAPPING[o_type]
    except KeyError:
        pass

    try:
        # because DefaultObservable takes a different set of arguments than the other observables...
        if o_class is None:
            return DefaultObservable(o_type, o_value, time=o_time, sort_order=sort_order, volatile=volatile)
        else:
            # otherwise it takes the default set of arguments
            return o_class(o_value, time=o_time, sort_order=sort_order, volatile=volatile)
    except ObservableValueError as e:
        logging.debug("invalid value {} for observable type {}: {}".format(o_value.encode('unicode_escape'), o_type, e))
        return None

def create_observable_from_dict(o_dict: dict) -> Optional[Observable]:
    """Creates an Observable instance from the given dictionary. Returns None if the dictionary is invalid."""
    o_type = o_dict[KEY_TYPE]
    o_class = OBSERVABLE_TYPE_MAPPING.get(o_type, DefaultObservable)
    return o_class.from_json(o_dict)


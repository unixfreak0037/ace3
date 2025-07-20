from saq.configuration.config import get_config_value
from saq.constants import CONFIG_TAG_CSS_CLASS, CONFIG_TAGS


def human_readable_size(size):
    from math import log2

    _suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']

    # determine binary order in steps of size 10 
    # (coerce to int, // still returns a float)
    order = int(log2(size) / 10) if size else 0
    # format file size
    # (.4g results in rounded numbers for exact matches and max 3 decimals, 
    # should never resort to exponent values)
    return '{:.4g} {}'.format(size / (1 << (order * 10)), _suffixes[order])

def create_histogram_string(data):
    """A convenience function that creates a graph in the form of a string.

    :param dict data: A dictionary, where the values are integers representing a count of the keys.
    :return: A graph in string form, pre-formatted for raw printing.
    """
    assert isinstance(data, dict)
    for key in data.keys():
        assert isinstance(data[key], int)
    total_results = sum([value for value in data.values()])
    txt = ""
    # order keys for printing in order (purly ascetics)
    ordered_keys = sorted(data, key=lambda k: data[k])
    results = []
    # longest_key used to calculate how many white spaces should be printed
    # to make the graph columns line up with each other
    longest_key = 0
    for key in ordered_keys:
        value = data[key]
        longest_key = len(key) if len(key) > longest_key else longest_key
        # IMPOSING LIMITATION: truncating keys to 95 chars, keeping longest key 5 chars longer
        longest_key = 100 if longest_key > 100 else longest_key
        percent = value / total_results * 100
        results.append((key[:95], value, percent, u"\u25A0" * (int(percent / 2))))
    # two for loops are ugly, but allowed us to count the longest_key -
    # so we loop through again to print the text
    for r in results:
        txt += "%s%s: %5s - %5s%% %s\n" % (int(longest_key - len(r[0])) * ' ', r[0], r[1],
                                           str(r[2])[:4], u"\u25A0" * (int(r[2] / 2)))
    return txt

def get_tag_css_class(tag):
    try:
        return get_config_value(CONFIG_TAG_CSS_CLASS, get_config_value(CONFIG_TAGS, tag))
    except:
        return 'label-default'
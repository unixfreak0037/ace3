from typing import TYPE_CHECKING, Callable, Union

if TYPE_CHECKING:
    from saq.analysis.analysis import Analysis
    from saq.analysis.observable import Observable


def recurse_down(target: Union["Analysis", "Observable"], callback: Callable[[Union["Analysis", "Observable"]], bool]) -> Union["Analysis", "Observable", None]:
    """Calls callback starting at target back to the RootAnalysis."""
    from saq.analysis.analysis import Analysis
    from saq.analysis.observable import Observable

    assert isinstance(target, Analysis) or isinstance(target, Observable)

    visited = [] # keep track of what we've looked at
    root = target.analysis_tree_manager.root_analysis

    def _recurse(target, callback):
        nonlocal visited, root
        # make sure we haven't already looked at this one
        if target in visited:
            return

        # are we at the end?
        if target is root:
            return

        visited.append(target)

        if isinstance(target, Observable):
            # find all Analysis objects that reference this Observable
            for analysis in root.all_analysis:
                for observable in analysis.observables:
                    # not sure the == part is needed but just in case I screw up later...
                    if target is observable or target == observable:
                        callback(analysis)
                        _recurse(analysis, callback)

        elif isinstance(target, Analysis):
            # find all Observable objects that reference this Analysis
            for observable in root.all_observables:
                for analysis in observable.all_analysis:
                    if analysis is target:
                        callback(observable)
                        _recurse(observable, callback)

    _recurse(target, callback)

def search_down(target, callback):
    """Searches from target down to RootAnalysis looking for callback(obj) to return True."""
    result = None

    def _callback(target):
        nonlocal result
        if result:
            return

        if callback(target):
            result = target

    recurse_down(target, _callback)
    return result

def recurse_tree(target, callback):
    """A utility function to run the given callback on every Observable and Analysis rooted at the given Observable or Analysis object."""
    from saq.analysis.analysis import Analysis
    from saq.analysis.observable import Observable
    assert isinstance(target, Analysis) or isinstance(target, Observable)

    def _recurse(target, visited, callback):
        callback(target)
        visited.append(target)

        if isinstance(target, Analysis):
            for observable in target.observables:
                if observable not in visited:
                    _recurse(observable, visited, callback)
        elif isinstance(target, Observable):
            for analysis in target.all_analysis:
                if analysis and analysis not in visited:
                    _recurse(analysis, visited, callback)

    _recurse(target, [], callback)


def find_observables_by_type(target, otype):
    from saq.analysis.observable import Observable
    observables = []
    def callback(target):
        if isinstance(target, Observable) and target.type == otype:
            observables.append(target)

    recurse_tree(target, callback)
    return observables
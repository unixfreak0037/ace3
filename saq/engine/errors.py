import inspect
from saq.analysis import Analysis, Observable


class AnalysisTimeoutError(RuntimeError):
    pass


class AnalysisFailedException(Exception):
    pass


class WaitForAnalysisException(Exception):
    """Thrown when we need to wait for analysis to occur on something.
    An AnalysisModule can call self.wait_for_analysis(observable, analysis) if it needs analysis performed by a
    given module on a given observable. That function will throw this exception if analysis has not
    occured yet, then the Engine will catch that and reorder things to perform that analysis next.
    """

    def __init__(self, observable, analysis, instance=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        assert isinstance(observable, Observable)
        assert inspect.isclass(analysis) and issubclass(analysis, Analysis)
        assert instance is None or isinstance(instance, str)
        self.observable = observable
        self.analysis = analysis
        self.instance = instance

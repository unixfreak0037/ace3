class ExcessiveFileDataSizeError(Exception):
    """Thrown when the size of the RootAnalysis on disk becomes larger than the configured limit."""
    pass

class ExcessiveObservablesError(Exception):
    """Thrown when too many observables have been added to the RootAnalysis object."""
    pass
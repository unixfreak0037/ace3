from saq.analysis.analysis_tree.analysis_tree_query import AnalysisTreeQueryEngine
from saq.analysis.observable_registry import ObservableRegistry


class AnalysisTreeValidator:
    """Handles validation of analysis tree integrity and structural consistency."""

    def __init__(self, query_engine: AnalysisTreeQueryEngine, observable_registry: ObservableRegistry):
        """Initialize the AnalysisTreeValidator.

        Args:
            root_analysis: The RootAnalysis instance
            query_engine: The AnalysisTreeQueryEngine for querying the tree
            observable_registry: The ObservableRegistry for checking registry consistency
        """
        self.query_engine = query_engine
        self.observable_registry = observable_registry

    def validate_tree_integrity(self) -> list[str]:
        """Validates the integrity of the analysis tree and returns a list of issues found."""
        issues: list[str] = []

        # Check that all analysis in observables reference the correct observable
        for observable in self.query_engine.all_observables:
            for analysis in observable.all_analysis:
                if analysis.observable is not observable:
                    issues.append(
                        f"Analysis {analysis} in observable {observable.id} has incorrect observable reference"
                    )

        # Check that all observables in analysis exist in the registry
        for analysis in self.query_engine.all_analysis:
            for observable in analysis.observables:
                if observable.id not in self.observable_registry.store:
                    issues.append(
                        f"Observable {observable.id} in analysis {analysis} not found in registry"
                    )

        return issues
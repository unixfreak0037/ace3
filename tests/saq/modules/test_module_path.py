import pytest

from saq.analysis.module_path import IS_MODULE_PATH, MODULE_PATH, SPLIT_MODULE_PATH
from saq.modules.context import AnalysisModuleContext
from saq.modules.adapter import AnalysisModuleAdapter


@pytest.mark.unit
def test_MODULE_PATH(test_context: AnalysisModuleContext):
    module_class_spec = 'some_module:some_class' # simple dummy module + class spec
    module_class_instance_spec = 'some_module:some_class:some_instance' # simple dummy module + class spec + instance
    assert MODULE_PATH(module_class_spec) == module_class_spec
    assert SPLIT_MODULE_PATH(MODULE_PATH(module_class_spec)) == ( 'some_module', 'some_class', None )
    assert MODULE_PATH(module_class_instance_spec) == module_class_instance_spec
    assert SPLIT_MODULE_PATH(MODULE_PATH(module_class_instance_spec)) == ( 'some_module', 'some_class', 'some_instance' )

    # pass by Analysis instance
    from saq.modules.test import BasicTestAnalysis
    assert MODULE_PATH(BasicTestAnalysis()) == 'saq.modules.test:BasicTestAnalysis'
    assert SPLIT_MODULE_PATH(MODULE_PATH(BasicTestAnalysis())) == ( 'saq.modules.test', 'BasicTestAnalysis', None )

    # pass by Analysis class
    from saq.modules.test import BasicTestAnalysis
    assert MODULE_PATH(BasicTestAnalysis) == 'saq.modules.test:BasicTestAnalysis'
    assert SPLIT_MODULE_PATH(MODULE_PATH(BasicTestAnalysis)) == ( 'saq.modules.test', 'BasicTestAnalysis', None )

    # pass by AnalysisModule instance
    from saq.modules.test import BasicTestAnalyzer
    assert MODULE_PATH(AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))) == 'saq.modules.test:BasicTestAnalysis'
    assert SPLIT_MODULE_PATH(MODULE_PATH(AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context)))) == ( 'saq.modules.test', 'BasicTestAnalysis', None )

    # same thing but with an instance value for the module
    from saq.modules.test import TestInstanceAnalysis
    analysis = TestInstanceAnalysis()
    analysis.instance = 'instance1'
    assert MODULE_PATH(analysis) == 'saq.modules.test:TestInstanceAnalysis:instance1'
    assert SPLIT_MODULE_PATH(MODULE_PATH(analysis)) == ( 'saq.modules.test', 'TestInstanceAnalysis', 'instance1' )

    # not a module path
    with pytest.raises(ValueError):
        MODULE_PATH("blah")

    with pytest.raises(ValueError):
        SPLIT_MODULE_PATH("blah")

    assert IS_MODULE_PATH("saq.modules.test:TestInstanceAnalysis:instance1")
    assert not IS_MODULE_PATH("blah")
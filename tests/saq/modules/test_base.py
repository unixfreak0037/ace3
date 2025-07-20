import pytest
from configparser import SectionProxy

from saq.engine.configuration_manager import get_analysis_module_config
from saq.modules.base_module import AnalysisModule
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.test import BasicTestAnalyzer


@pytest.mark.unit
def test_get_analysis_module_config(test_context):
    assert isinstance(get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))), SectionProxy)

    class CustomAnalysisModule(AnalysisModule):
        pass

    #with pytest.raises(RuntimeError):
        #get_analysis_module_config(CustomAnalysisModule())

    with pytest.raises(AssertionError):
        get_analysis_module_config(BasicTestAnalyzer)
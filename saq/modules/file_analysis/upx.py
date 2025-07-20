import logging
import os
import re
from subprocess import PIPE, Popen
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_pe_file
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class UPXAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            'stdout': None,
            'stderr': None,
            'output_file': None,
            'error': None,
        }

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if self.details['error']:
            return f"UPX decompression failed: {self.details['error']}"

        return f"UPX decompression success: {self.details['output_file']}"


class UPXAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('upx')

    @property
    def generated_analysis_type(self):
        return UPXAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def test_upx(self, path):
        """Returns True if the upx command returns OK for the file at path."""
        _stdout, _stderr = Popen(['upx', '-t', path], stdout=PIPE, stderr=PIPE).communicate()
        ok_regex = re.compile(b'^testing .* \\[OK\\]$', re.M)
        return ok_regex.search(_stdout) is not None

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        if not is_pe_file(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        if not self.test_upx(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        output_path = f'{local_file_path}.upx.exe'
        try:
            analysis.details['stdout'], analysis.details['stderr'] = Popen(['upx', '-d', f'-o{output_path}', local_file_path], stdout=PIPE, stderr=PIPE).communicate()
            analysis.details['output_file'] = os.path.basename(output_path)
        except Exception as e:
            analysis.details['error'] = str(e)
            logging.error(f"upx failed for {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        file_observable = analysis.add_file_observable(output_path, volatile=True)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.add_tag('upx')
            _file.copy_directives_to(file_observable)

        return AnalysisExecutionResult.COMPLETED

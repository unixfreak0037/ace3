import logging
import os
from subprocess import PIPE, Popen
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_lnk_file
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class LnkParseAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'stdout': None,
            'stderr': None,
            'error': None,
            'lnk_count': 0
        }

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if self.details['error']:
            return f"LnkParse Analysis: {self.details['error']}"

        lnk_word = 'lnk' if self.details['lnk_count'] == 1 else 'lnks'

        return f"LnkParse Analysis: {self.details['lnk_count']} {lnk_word} parsed"


class LnkParseAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('lnkparse')

    @property
    def generated_analysis_type(self):
        return LnkParseAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        if is_lnk_file(local_file_path) == False:
            logging.debug(f'{local_file_path} is not a .lnk file')
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        target_dir = f'{local_file_path}.lnkparser'
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, 'lnkparser.out')
        try:
            # Parse the lnk file
            logging.debug("Attempting to call lnk parse")
            analysis.details['stdout'], analysis.details['stderr'] = Popen(['lnkparse', local_file_path], stdout=PIPE, stderr=PIPE).communicate()
            
            with open(target_file, 'wb') as fp:
                fp.write(analysis.details['stdout'])
        except Exception as e:
            analysis.details['error'] = str(e)
            logging.info(f'LnkParse failed for {local_file_path}')
        
        # Add any parsed lnks as file observables
        for f in os.listdir(target_dir):
            if f.endswith('.out'):
                analysis.details['lnk_count'] += 1
                full_path = os.path.join(target_dir, f)
                file_observable = analysis.add_file_observable(full_path)
                if file_observable:
                    file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                    file_observable.add_tag('lnk')
        
        logging.debug(f"Parsed {analysis.details['lnk_count']} lnk file")

        return AnalysisExecutionResult.COMPLETED
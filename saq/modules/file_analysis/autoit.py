import logging
import os
from subprocess import PIPE, Popen
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_autoit
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class AutoItAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'stdout': None,
            'stderr': None,
            'error': None,
            'num_scripts': 0,
        }

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if self.details['error']:
            return f"AutoIt Decompilation Analysis: {self.details['error']}"

        script_word = 'script' if self.details['num_scripts'] == 1 else 'scripts'
        return f"AutoIt Decompilation Analysis: {self.details['num_scripts']} {script_word} decompiled"


class AutoItAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('unautoit')

    @property
    def generated_analysis_type(self):
        return AutoItAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        if not is_autoit(local_file_path):
            logging.debug(f'{local_file_path} is not an autoit executable')
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag('autoit')

        analysis = self.create_analysis(_file)
        output_path = f'{local_file_path}.autoit'
        analysis.details['output_dir'] = output_path
        try:
            # Store the "unautoit list" in the analysis details
            analysis.details['stdout'], analysis.details['stderr'] = Popen(['unautoit', 'list', local_file_path], stdout=PIPE, stderr=PIPE).communicate()

            # Decompile the executable.
            # To avoid incorrect directory permissions, manually create the output dir first. The unautoit utility
            # seems to create directories without the executable permission, which causes it to error out and not
            # store the decompiled scripts in the directory.
            os.makedirs(output_path)
            _, _ = Popen(['unautoit', 'extract-all', '--output-dir', output_path, local_file_path], stdout=PIPE, stderr=PIPE).communicate()
        except Exception as e:
            analysis.details['error'] = str(e)
            logging.info(f'AutoIt decompilation failed for {local_file_path}')

        # Add any decompiled .au3 scripts as file observables
        for f in os.listdir(output_path):
            if f.endswith('.au3'):
                analysis.details['num_scripts'] += 1
                full_path = os.path.join(output_path, f)
                file_observable = analysis.add_file_observable(full_path, volatile=True)
                if file_observable:
                    file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                    file_observable.add_tag('autoit')
                    # avoid recursion -- no idea if this is possible but would rather avoid it
                    file_observable.exclude_analysis(self)

        logging.debug(f'AutoIt decompiled {analysis.details["num_scripts"]} scripts')

        return AnalysisExecutionResult.COMPLETED
import logging
import os
import pprint

import exiftool
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE, R_EXTRACTED_FROM
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_office_file, is_ole_file, is_pdf_file
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class ExifAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'exifdata': None,
            'stdout': None,
            'stderror': None,
            'error': None,
        }

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if self.details['error']:
            return f"Exiftool Analysis: {self.details['error']}"

        return f"Exiftool Analysis Completed"


class ExifAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('exiftool')

    @property
    def generated_analysis_type(self):
        return ExifAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.hash import FileHashAnalyzer
        from saq.modules.file_analysis.file_type import FileTypeAnalyzer

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # self.wait_for_analysis(_file, FileTypeAnalysis)
        if not is_office_file(_file) and not is_ole_file(local_file_path) and not is_pdf_file(local_file_path):
            logging.debug(f'{local_file_path} is not an office document and not a pdf')
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        try:
            # Get exif data
            with exiftool.ExifToolHelper() as et:
                metadata = et.get_metadata(local_file_path)
        except Exception as e:
            analysis.details['error'] = str(e)
            logging.info(f'Exif data extraction failed for {local_file_path}: {e}')
            return AnalysisExecutionResult.COMPLETED

        # return nicely formatted exif data
        exifdata =  pprint.pformat(metadata)

        # analysis.details['stdout'], analysis.details['stderr'] = Popen(['exiftool', local_file_path], stdout=PIPE, stderr=PIPE).communicate()

        analysis.details['exifdata'] = exifdata
        if 'Error: Exif data extraction failed for' in metadata:
            return AnalysisExecutionResult.COMPLETED

        target_dir = f'{local_file_path}.exif'
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, 'exiftool.out')
        # Write pretty output to target file
        with open(target_file, 'w') as fp:
             fp.write(exifdata)
            #fp.write(analysis.details['stdout'])

        analysis.details['output_dir'] = target_dir
        file_observable = analysis.add_file_observable(target_file)
        if file_observable:
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            file_observable.exclude_analysis(FileHashAnalyzer)
            file_observable.exclude_analysis(FileTypeAnalyzer)
            #file_observable.add_tag('exif')

        logging.debug(f'Exif data collection completed.')

        return AnalysisExecutionResult.COMPLETED
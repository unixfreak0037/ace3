import logging
import os.path

from saq.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE, DIRECTIVE_ORIGINAL_EMAIL, R_EXTRACTED_FROM
from saq.modules import AnalysisModule
from saq.mime_extractor import parse_mime, parse_active_mime
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path

class HiddenMIMEAnalysis(Analysis):
    KEY_EXTRACTED_FILES = "extracted_files"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            HiddenMIMEAnalysis.KEY_EXTRACTED_FILES: []
        }

    @property
    def extracted_files(self):
        return self.details[HiddenMIMEAnalysis.KEY_EXTRACTED_FILES]

    @extracted_files.setter
    def extracted_files(self, value):
        self.details[HiddenMIMEAnalysis.KEY_EXTRACTED_FILES] = value

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if not self.extracted_files:
            return None

        return f"Hidden MIME Analysis: extracted {len(self.extracted_files)} files"

class HiddenMIMEAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return HiddenMIMEAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        # do not run this on 
        # - emails
        if _file.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
            return AnalysisExecutionResult.COMPLETED

        if _file.file_name == "email.rfc822":
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is not None and file_type_analysis.mime_type == "message/rfc822":
            return AnalysisExecutionResult.COMPLETED

        target_dir = f"{local_file_path}.mime"
        extracted_files = parse_mime(local_file_path, target_dir)
        if not extracted_files:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        analysis.extracted_files = extracted_files
        for file_path in analysis.extracted_files:
            file_observable = analysis.add_file_observable(file_path)
            if file_observable:
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)

        return AnalysisExecutionResult.COMPLETED

class ActiveMimeAnalysis(Analysis):
    KEY_EXTRACTED_FILE = "extracted_file"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            ActiveMimeAnalysis.KEY_EXTRACTED_FILE: []
        }

    @property
    def extracted_file(self):
        return self.details[ActiveMimeAnalysis.KEY_EXTRACTED_FILE]

    @extracted_file.setter
    def extracted_file(self, value):
        self.details[ActiveMimeAnalysis.KEY_EXTRACTED_FILE] = value

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if not self.extracted_file:
            return None

        return f"ActiveMime Analysis: extracted ActiveMime document"

class ActiveMimeAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return ActiveMimeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        target_path = f"{local_file_path}.activemime"
        if parse_active_mime(local_file_path, target_path):
            analysis = self.create_analysis(_file)
            analysis.extracted_file = target_path
            file_observable = analysis.add_file_observable(target_path)
            if file_observable:
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                file_observable.add_tag("activemime")

        return AnalysisExecutionResult.COMPLETED

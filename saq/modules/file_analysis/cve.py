import logging
import os
import re
import shutil
from subprocess import PIPE, Popen, TimeoutExpired
import tempfile
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, G_TEMP_DIR, AnalysisExecutionResult
from saq.environment import g
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class CVE_2021_30657_Analysis(Analysis):
    """Does this DMG file have a script for a file in /Contents/MacOS/"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "suspect_files": {} # key = file_path, value = mime_type
        }

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if not self.details["suspect_files"]:
            return None

        output = []
        for file_path, mime_type in self.details["suspect_files"].items():
            output.append(f"{file_path} has mime type {mime_type}")

        return "CVE-2021-30657 Analysis: " + " | ".join(output)


class CVE_2021_30657_Analyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('7z')

    @property
    def generated_analysis_type(self):
        return CVE_2021_30657_Analysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.dmg import DMGAnalysis

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # file should end with .img (from the DMGAnalyzer) and have macos and dmg tags
        if not local_file_path.lower().endswith(".img"):
            return AnalysisExecutionResult.COMPLETED

        if not _file.has_tag("macos") or not _file.has_tag("dmg"):
            return AnalysisExecutionResult.COMPLETED

        # start extracting and analyzing all the files listed in the report
        dmg_analysis = _file.redirection.get_and_load_analysis(DMGAnalysis)
        if not dmg_analysis:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        # use a temporary directory for this that we can clean up later
        temp_dir = tempfile.mkdtemp(dir=g(G_TEMP_DIR))

        try:
            # "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/1302"
            for line in dmg_analysis.details["file_list"]:
                if not "/Contents/MacOS/" in line:
                    continue

                # parse out the file name
                RE_7Z_FILE_ENTRY = re.compile(r"^.+?\d+\s+\d+\s+(.+)$")
                m = RE_7Z_FILE_ENTRY.match(line)
                if not m:
                    continue

                file_path = m.group(1)

                # extract this one file
                process = Popen(["7z", "x", f"-o{temp_dir}", local_file_path, file_path], stdout=PIPE, stderr=PIPE)
                _stdout, _stderr = process.communicate()

                target_file = os.path.join(temp_dir, file_path)
                if not os.path.exists(target_file):
                    logging.error(f"failed to extracted {file_path}: stdout: {_stdout} stderr: {_stderr}")
                    continue

                # check the mime type of this file
                process = Popen(['file', '-b', '--mime-type', '-L', target_file], stdout=PIPE, stderr=PIPE, universal_newlines=True)
                stdout, stderr = process.communicate()

                # does this mime type have "script" in it?
                if "script" in stdout:
                    # possible attack
                    target_dir = os.path.join(self.get_root().storage_dir, "cve_2021_30657")
                    if not os.path.isdir(target_dir):
                        os.makedirs(target_dir)

                    target_path = os.path.join(target_dir, os.path.basename(target_file))
                    shutil.copy(target_file, target_path)
                    file_observable = analysis.add_observable_by_spec(F_FILE, os.path.relpath(target_path, start=self.get_root().storage_dir))
                    if file_observable:
                        file_observable.add_detection_point(f"Possible CVE-2021-30657 attack: a file in DMG format file {_file} is a script")
                        file_observable.add_tag("CVE-2021-30657")
                        analysis.details["suspect_files"][file_path] = stdout.strip()

        finally:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error(f"unable to delete directory {temp_dir}: {e}")

        return AnalysisExecutionResult.COMPLETED
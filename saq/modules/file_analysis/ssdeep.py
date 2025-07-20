import logging
import os
import re
from subprocess import PIPE, Popen
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class SsdeepAnalysis(Analysis):
    """Does this file match any other files by fuzzy hash?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            'matches': [], # [] of { 'file': blah, 'score': int }
        }

    def generate_summary(self):
        if len(self.details['matches']) > 0:
            return "Ssdeep Analysis ({0} matches {1}% highest match)".format(
                len(self.details['matches']), max([x['score'] for x in self.details['matches']]))
        return None

class SsdeepAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_config_exists('ssdeep_hashes')
        self.verify_path_exists(self.config['ssdeep_hashes'])
        self.verify_config_exists('maximum_size')
        self.verify_config_exists('ssdeep_match_threshold')
        self.verify_program_exists('ssdeep')

    @property
    def ssdeep_hashes(self):
        return self.config['ssdeep_hashes']

    @property
    def maximum_size(self):
        return self.config.getint('maximum_size')

    @property
    def ssdeep_match_threshold(self):
        return self.config.getint('ssdeep_match_threshold')

    @property
    def generated_analysis_type(self):
        return SsdeepAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # don't bother for files that are really small
        file_size = os.path.getsize(local_file_path)
        if file_size < 1024:
            logging.debug("{} too small for ssdeep analysis".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        # and bail if the file is too big
        if file_size > self.maximum_size:
            logging.debug("{} too large ({}) for ssdeep analysis".format(local_file_path, file_size))
            return AnalysisExecutionResult.COMPLETED

        logging.debug("analyzing file {}".format(local_file_path))
        p = Popen(['ssdeep', '-m', self.ssdeep_hashes, local_file_path], 
            stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (stdout, stderr) = p.communicate()

        if len(stderr) > 0:
            logging.debug("ssdeep returned errors for {}".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        analysis = None

        for line in stdout.split('\n'):
            # example output:
            # /opt/mwzoo/data/pos/frameworkpos/1/a5dc57aea5f397c2313e127a6e01aa00 matches all_the_hashes.ssdeep:/opt/mwzoo/data/pos/frameworkpos/1/a5dc57aea5f397c2313e127a6e01aa00.sample (100)
            if line == '':
                continue

            m = re.match(r'^.+? matches [^:]+:(.+) \(([0-9]{1,3})\)$', line)
            if not m:
                logging.error("unexpected ssdeep output: {}".format(line))
                continue

            matched_file = m.group(1)
            ssdeep_score = 0

            try:
                ssdeep_score = int(m.group(2))
            except Exception as e:
                logging.error("unable to parse {} as integer".format(ssdeep_score))

            if ssdeep_score >= self.ssdeep_match_threshold:
                _file.add_tag('ssdeep')
                _file.add_directive(DIRECTIVE_SANDBOX)
                if not analysis:
                    analysis = self.create_analysis(_file)

                analysis.details['matches'].append({'file': matched_file, 'score': int(ssdeep_score)})

        return AnalysisExecutionResult.COMPLETED
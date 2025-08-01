from datetime import datetime
import logging
import os
import re
import shutil
from saq.analysis import Analysis
from saq.constants import ANALYSIS_TYPE_BRO_SMTP, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, DIRECTIVE_ORIGINAL_SMTP, F_EMAIL_ADDRESS, F_EMAIL_CONVERSATION, F_FILE, F_IPV4, create_email_conversation, AnalysisExecutionResult
from saq.environment import get_data_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.email.constants import KEY_CONNECTION_ID, KEY_ENV_MAIL_FROM, KEY_ENV_RCPT_TO, KEY_SOURCE_IPV4, KEY_SOURCE_PORT
from saq.observables.file import FileObservable

class BroSMTPStreamAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_CONNECTION_ID: None,
            KEY_ENV_MAIL_FROM: None,
            KEY_ENV_RCPT_TO: None,
        }

    @property
    def connection_id(self):
        return self.details[KEY_CONNECTION_ID]

    @connection_id.setter
    def connection_id(self, value):
        self.details[KEY_CONNECTION_ID] = value

    @property
    def env_mail_from(self):
        return self.details[KEY_ENV_MAIL_FROM]

    @env_mail_from.setter
    def env_mail_from(self, value):
        self.details[KEY_ENV_MAIL_FROM] = value

    @property
    def env_rcpt_to(self):
        return self.details[KEY_ENV_RCPT_TO]

    @env_rcpt_to.setter
    def env_rcpt_to(self, value):
        self.details[KEY_ENV_RCPT_TO] = value

    def generate_summary(self):
        result = "BRO SMTP Stream Analysis - "
        if not self.connection_id:
            result += 'no email extracted'
        else:
            if KEY_CONNECTION_ID in self.details:
                result += '({}) '.format(self.details[KEY_CONNECTION_ID])
            if KEY_ENV_MAIL_FROM in self.details:
                result += 'MAIL FROM {} '.format(self.details[KEY_ENV_MAIL_FROM])
            if KEY_ENV_RCPT_TO in self.details:
                result += 'RCPT TO {} '.format(','.join(self.details[KEY_ENV_RCPT_TO]))

        return result

# regular expressions for parsing smtp files generated by bro extraction (see bro/ directory)
REGEX_BRO_SMTP_SOURCE_IPV4 = re.compile(r'^([^:]+):(\d+).*$')
REGEX_BRO_SMTP_MAIL_FROM = re.compile(r'^> MAIL FROM:<([^>]+)>.*$')
REGEX_BRO_SMTP_RCPT_TO = re.compile(r'^> RCPT TO:<([^>]+)>.*$')
REGEX_BRO_SMTP_DATA = re.compile(r'^< DATA 354.*$')
REGEX_BRO_SMTP_RSET = re.compile(r'^< RSET.*$')

class BroSMTPStreamAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return BroSMTPStreamAnalysis

    @property
    def required_directives(self):
        return [ DIRECTIVE_ORIGINAL_SMTP ]

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)

        # did we end up whitelisting the email?
        # this actually shouldn't even fire because if the email is whitelisted then the work queue is ignored
        # for this analysis
        if self.get_root().whitelisted:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        path = _file.full_path

        # the current message we're parsing in the case of multiple emails coming in over the same connection
        smtp_message_index = 0 

        try:
            with open(path, 'r', errors='ignore') as fp:
                source_ipv4 = None
                source_port = None
                envelope_from = None
                envelope_to = []

                # the first line of the file has the source IP address of the smtp connection
                # in the following format: 172.16.139.143:38668/tcp

                line = fp.readline()
                m = REGEX_BRO_SMTP_SOURCE_IPV4.match(line)

                if not m:
                    raise ValueError("unable to parse soure address from {} ({})".format(path, line.strip()))
                else:
                    source_ipv4 = m.group(1)
                    source_port = m.group(2)

                    logging.debug("got source ipv4 {} port {} for {}".format(source_ipv4, source_port, path))

                # the second line is the time (in epoch UTC) that bro received the file
                line = fp.readline()
                self.get_root().event_time = datetime.utcfromtimestamp(int(line.strip()))
                logging.debug("got event time {} for {}".format(self.get_root().event_time, path))

                STATE_SMTP = 1
                STATE_DATA = 2

                state = STATE_SMTP
                rfc822_path = None
                rfc822_fp = None

                def _reset_state():
                    nonlocal rfc822_fp, source_ipv4, source_port, envelope_from, envelope_to, state

                    rfc822_fp = None
                    source_ipv4 = None
                    source_port = None
                    envelope_from = None
                    envelope_to = []

                    state = STATE_SMTP

                def _finalize():
                    # called when we detect the end of an SMTP stream OR the end of the file (data)
                    nonlocal rfc822_fp, source_ipv4, source_port, envelope_from, envelope_to, state

                    rfc822_fp.close()

                    logging.info("finished parsing {} from {}".format(rfc822_path, path))

                    # submit this for analysis...
                    email_file = analysis.add_file_observable(rfc822_path)
                    if email_file:
                        email_file.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                        # we don't scan the email as a whole because of all the random base64 data
                        # that randomly matches various indicators from crits
                        # instead we rely on all the extraction that we do and scan the output of those processes
                        email_file.add_directive(DIRECTIVE_NO_SCAN)
                        # make sure we archive it
                        email_file.add_directive(DIRECTIVE_ARCHIVE)

                    analysis.details = {
                        # the name of the file will equal the bro connection id
                        KEY_CONNECTION_ID: os.path.basename(path),
                        KEY_SOURCE_IPV4: source_ipv4,
                        KEY_SOURCE_PORT: source_port,
                        KEY_ENV_MAIL_FROM: envelope_from,
                        KEY_ENV_RCPT_TO: envelope_to,
                    }

                    self.get_root().description = 'BRO SMTP Scanner Detection - ' 

                    if source_ipv4:
                        observable = analysis.add_observable_by_spec(F_IPV4, source_ipv4)

                    if envelope_from:
                        observable = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, envelope_from)
                        self.get_root().description += 'From {} '.format(envelope_from)

                    if envelope_to:
                        for to in envelope_to:
                            observable = analysis.add_observable_by_spec(F_EMAIL_ADDRESS, to)
                            if envelope_from:
                                observable = analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, 
                                                                     create_email_conversation(envelope_from, to))

                        self.get_root().description += 'To {} '.format(','.join(envelope_to))

                    _reset_state()

                # smtp is pretty much line oriented
                while True:
                    line = fp.readline()
                    if line == '':
                        break

                    if state == STATE_SMTP:
                        m = REGEX_BRO_SMTP_MAIL_FROM.match(line)
                        if m:
                            envelope_from = m.group(1)
                            logging.debug("got envelope_from {} for {}".format(envelope_from, path))
                            continue

                        m = REGEX_BRO_SMTP_RCPT_TO.match(line)
                        if m:
                            envelope_to.append(m.group(1))
                            logging.debug("got envelope_to {} for {}".format(envelope_to, path))
                            continue

                        m = REGEX_BRO_SMTP_DATA.match(line)
                        if m:
                            state = STATE_DATA
                            rfc822_path = self.get_root().create_file_path(f'smtp.{smtp_message_index}.email.rfc822')
                            smtp_message_index += 1
                            rfc822_fp = open(rfc822_path, 'w')
                            logging.debug("created {} for {}".format(rfc822_path, path))
                            continue

                        m = REGEX_BRO_SMTP_RSET.match(line)
                        if m:
                            logging.debug(f"detected RSET for {path}")
                            _reset_state()
                            continue

                        # any other command we skip
                        logging.debug(f"skipping SMTP command {line.strip()}")
                        continue

                    # otherwise we're reading DATA and looking for the end of that
                    if line.strip() == ('> . .'):
                        _finalize()
                        continue

                    rfc822_fp.write(line)
                    continue

                # did the file end while we were reading SMTP data?
                if state == STATE_DATA:
                    _finalize()

            return AnalysisExecutionResult.COMPLETED

        except Exception as e:
            logging.error("unable to parse smtp stream {}: {}".format(_file, e))
            report_exception()
            shutil.copy(_file.full_path, os.path.join(get_data_dir(), 'review', 'smtp'))
            return AnalysisExecutionResult.COMPLETED

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        from saq.modules.email.rfc822 import EmailAnalysis
        if self.get_root().alert_type != ANALYSIS_TYPE_BRO_SMTP:
            return AnalysisExecutionResult.COMPLETED

        # find the email we extracted from the stmp stream
        email_observable = self.get_root().find_observable(lambda o: o.has_directive(DIRECTIVE_ORIGINAL_EMAIL))
        if email_observable is None:
            return AnalysisExecutionResult.COMPLETED

        email_analysis = email_observable.get_and_load_analysis(EmailAnalysis)
        if email_analysis is None or isinstance(email_analysis, bool):
            return AnalysisExecutionResult.COMPLETED

        if email_analysis.decoded_subject is not None:
            self.get_root().description += ' Subject: {}'.format(email_analysis.decoded_subject)
        elif email_analysis.subject is not None:
            self.get_root().decoded_subject += ' Subject: {}'.format(email_analysis.subject)

        return AnalysisExecutionResult.COMPLETED
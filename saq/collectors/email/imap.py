import logging
from typing import Union

from socks import create_connection
from socks import PROXY_TYPE_SOCKS4
from socks import PROXY_TYPE_SOCKS5
from socks import PROXY_TYPE_HTTP

import imaplib
from imaplib import IMAP4
from email import message_from_bytes
from email.message import Message
from email.utils import parseaddr, getaddresses, parsedate_to_datetime

from saq.configuration import get_config
from saq.proxy import proxies
from saq.collectors.email import RemoteEmailCollector
from saq.collectors.email.base import EmailCollectionBaseProcessor, EmailObject, EmailUser
from saq.error import report_exception


# Credit to https://gist.github.com/sstevan/efccf3d5d3e73039c21aa848353ff52f
class SocksIMAP4(IMAP4):
    """
    IMAP service trough SOCKS proxy. PySocks module required.
    """

    PROXY_TYPES = {"socks4": PROXY_TYPE_SOCKS4,
                   "socks5": PROXY_TYPE_SOCKS5,
                   "http": PROXY_TYPE_HTTP}

    def __init__(self, host, port=None, proxy_addr=None, proxy_port=None,
                 rdns=True, username=None, password=None, proxy_type="http"):
        self.proxy_addr = proxy_addr
        self.proxy_port = proxy_port
        self.rdns = rdns
        self.username = username
        self.password = password
        self.proxy_type = SocksIMAP4.PROXY_TYPES[proxy_type.lower()]

        IMAP4.__init__(self, host, port)

    def _create_socket(self, timeout):
        return create_connection((self.host, self.port), proxy_type=self.proxy_type, proxy_addr=self.proxy_addr,
                                 proxy_port=self.proxy_port, proxy_rdns=self.rdns, proxy_username=self.username,
                                 proxy_password=self.password)


class IMAPEmailObject(EmailObject):
    """IMAP-specific version of the EmailObject class."""

    def __init__(self, message_object: Message = None, message_data: bytes = None):
        super().__init__(message_object)
        self._obj_type = 'imap'
        self._mime_content = message_data

        # Use helper methods from email.message class to parse out metadata
        try:
            self._to_recipients = [EmailUser(_[1]) for _ in getaddresses(self._message.get_all('to', []))]
            self._cc_recipients = [EmailUser(_[1]) for _ in getaddresses(self._message.get_all('cc', []))]
            self._bcc_recipients = [EmailUser(_[1]) for _ in getaddresses(self._message.get_all('bcc', []))]
            self._sender = EmailUser(parseaddr(self._message.get('from'))[1])
            self._message_id = self._message.get('Message-ID').strip()
            self._subject = self._message.get('Subject').strip()
            self._datetime_received = parsedate_to_datetime(self._message.get('Date').strip())
        except Exception as e:
            logging.error(f"unable to parse email: {e}")
            report_exception()

    @property
    def subject(self):
        return self._subject

    @property
    def datetime_received(self):
        return self._datetime_received

    @property
    def message_id(self):
        if self._message_id:
            return self._message_id

    @property
    def id(self):
        if self._message_id:
            return self._message_id

    @property
    def body(self):
        """Body is unused, unnecessary to implement"""
        return None

    @property
    def mime_content(self):
        return self._mime_content


class IMAPEmailCollectionProcessor(EmailCollectionBaseProcessor):
    """IMAP-specific collection processor.

    This class knows how to get email messages from various folders."""

    def __init__(self, collector: RemoteEmailCollector, *args, **kwargs) -> None:
        super().__init__(collector, *args, **kwargs)
        self.password = None
        self.server = None
        self.server_port = None
        self.use_proxy = False
        self.proxy_key = None
        self.mail = None

    def load_from_config(self, section: str, *args, **kwargs) -> None:
        """Load from config, initialize base class, and then add
            IMAP-specific configuration."""
        logging.debug(f'email account loading from {section}')
        super().load_from_config(section, **kwargs)
        _config = kwargs.get('config') or get_config()
        self.password = _config[section].get('password', fallback=None)
        self.server = _config[section].get('server', fallback=None)
        self.server_port = _config[section].getint('server_port', fallback=None)
        self.use_proxy = _config[section].getboolean('use_proxy', fallback=False)
        if self.use_proxy:
            self.proxy_key = _config[section].get('proxy_key')

    def auth_with_proxy(self) -> SocksIMAP4:
        """If using a proxy, a special class must be used to load imap through the proxy."""

        # In order to init the special imap class, we need to extract specific parts of the proxy to use as variables
        # No special purpose to using the 'http' proxy, we just need a proxy string
        proxy = proxies(self.proxy_key)['http']
        proxy_type = 'http' if 'http' in proxy else 'socks5' if '5' in proxy else 'socks4'
        from urllib.parse import urlparse
        parsed_url = urlparse(proxy)
        host = parsed_url.hostname
        port = parsed_url.port
        username = None
        password = None

        if proxy_type == 'http':
            username = parsed_url.username
            password = parsed_url.password

        logging.debug(f"connecting to server {self.server} port {self.server_port} via {host}")
        return SocksIMAP4(self.server, port=self.server_port, proxy_addr=host, proxy_port=port, username=username, password=password, proxy_type=proxy_type)

    def initialize_auth(self, imap_class=imaplib.IMAP4, **kwargs) -> bool:
        """Perform authentication specific for IMAP."""
        logging.debug(f'initializing imap auth for {self.section}')

        if not self.password:
            logging.error(f"no password given for {self.section}. authentication will not be"
                          f"attempted in order to prevent account lockout.")
            return False

        if self.use_proxy:
            self.mail = self.auth_with_proxy()
        else:
            self.mail = imap_class(self.server)

        if not self.mail:
            logging.warning("unable to initialize auth")
            return False

        response_code, data = self.mail.login(user=self.target_mailbox, password=self.password)
        if response_code != 'OK':
            logging.error(f"Unable to initialize imap authentication for {self.target_mailbox}: {response_code}")
            return False

        return True

    def select_folder(self, folder: str) -> bool:
        """Select a folder within loaded mailbox."""
        response_code, data = self.mail.select(folder)
        if response_code != 'OK':
            logging.error(f"Unable to select folder '{folder}' in {self.target_mailbox}: {response_code}")
            return False

        return True

    def get_all_message_ids(self) -> list:
        """Get all *IMAP* message IDs from selected folder."""
        response_code, all_message_ids = self.mail.search(None, 'ALL')
        if response_code != 'OK':
            logging.error(f"Unable to get message IDs from mailbox {self.target_mailbox}: {response_code}")
            return []

        return all_message_ids[0].split()

    def get_message_content(self, message_id: str) -> Union[bytes, None]:
        """Get RFC822 content for a given message using its respective IMAP message ID"""
        response_code, response_data = self.mail.fetch(message_id, '(RFC822)')
        if response_code != 'OK':
            logging.error(f"Unable to get message {message_id} from mailbox {self.target_mailbox}: {response_code}")
            return None

        # imap always returns the rfc822 data in nested list/tuple combo that is always in [0][1] position
        # but make sure that the data is actually bytes, otherwise there may have been an issue fetching the message
        data = response_data[0][1]
        if isinstance(data, bytes):
            return data

        logging.warning(f"Fetching {message_id} did not return bytes. response_data: {response_data}")
        return None

    def _execute(self, *args, **kwargs) -> bool:
        """Handle getting the email messages from given folder in the target mailbox.

        This method also handles persistent storage and unmatched email handling."""

        if not self.initialize_auth(**kwargs):
            return False

        _ = self.register_persistence_source(self._persistence_source_key)

        for folder in self.folders:
            if not self.select_folder(folder):
                return False

            total_count = 0
            already_processed_count = 0
            error_count = 0
            unmatched_count = 0

            logging.info(f"checking for emails in {self.target_mailbox} target {folder}")
            all_message_ids = self.get_all_message_ids()
            logging.info(f"processing {len(all_message_ids)} emails")
            for imap_message_id in all_message_ids:
                if self.collector.is_service_shutdown:
                    return False

                total_count += 1
                try:
                    logging.info(f"downloading message {imap_message_id}")
                    message_data = self.get_message_content(imap_message_id)
                    if not message_data:
                        return False

                    message = message_from_bytes(message_data)

                    if self.persistent_data_exists(message['Message-ID']):
                        already_processed_count += 1
                        if self.delete_emails:
                            self.handle_delete_message(imap_message_id)

                        continue

                    logging.info(f'creating imap email object from {message["Message-ID"]}')
                    message_object = IMAPEmailObject(message, message_data)
                    message_matched = self.process_email(message_object)

                    # no matter if it matched or not we want to remember that we already looked at it
                    self.save_persistent_key(message["Message-ID"])

                    # did we not match against the email? (was not it something we actually consumed?)
                    if not message_matched:
                        unmatched_count += 1
                        self.handle_unmatched(message_object)
                        continue

                    # should we move this inside the above try except so that we only delete emails if we successfully processed them?
                    if self.delete_emails:
                        self.handle_delete_message(imap_message_id)

                except imaplib.IMAP4.abort as e:
                    logging.warning(f"Connection interrupted & IMAP aborted; trying again later: {e}")
                    return False

                except Exception as e:
                    logging.error(f'unable to process email: {e.__class__}, {e}')
                    error_count += 1
                    report_exception()
                    continue

            logging.info(f"'{self.target_mailbox}:{folder}' metrics - total: {total_count}, already processed: "
                         f"{already_processed_count}, unmatched: {unmatched_count}, errors: {error_count}")

        if self.delete_emails:
            self.handle_expunge()

        try:
            self.mail.logout()
        except Exception as e:
            logging.warning(f"unable to logout of IMAP service: {e}")

        return True

    def handle_unmatched(self, message: IMAPEmailObject) -> None:
        if self.save_unmatched_locally:
            self.handle_unmatched_locally(message)
        if self.save_unmatched_remotely:
            self.handle_unmatched_remotely(message)

    def handle_unmatched_remotely(self, message: IMAPEmailObject) -> None:
        """Define how to handle unmatched email messages remotely in IMAP.
                    Not currently used and therefore not implemented at the moment."""
        return

    def handle_unmatched_locally(self, message: IMAPEmailObject) -> None:
        """Define how to handle unmatched email messages locally.
                    Not currently used and therefore not implemented at the moment."""
        return

    def handle_delete_message(self, message_id: str) -> None:
        try:
            # set the delete flag
            logging.info(f"setting imap message {message_id} to deleted")
            self.mail.store(message_id, '+FLAGS', '\\Deleted')
        except Exception as e:
            logging.error(f'unable to delete email: {e}')
            report_exception()

    def handle_expunge(self) -> None:
        """Calls EXPUNGE which deletes all emails marked for deletion by handle_delete_message."""
        try:
            # delete messages flagged for deletion
            logging.info(f"expunging all deleted emails")
            self.mail.expunge()
        except Exception as e:
            logging.error(f'unable to expunge email: {e}')
            report_exception()

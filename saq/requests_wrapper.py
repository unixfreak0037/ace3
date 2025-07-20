import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry # pyright: ignore

# fake a list from min to max excluding excluded
class Range():
    def __init__(self, minimum, maximum, exclude):
        self.minimum = minimum
        self.maximum = maximum
        self.exclude = exclude

    def __contains__(self, item: int):
        return self.minimum <= item < self.maximum and item not in self.exclude

def raise_for_status(reponse):
    reponse.raise_for_status()

class Session(requests.Session):
    def __init__(self, base_url='', timeout=120, max_retries=7, backoff_factor=1, halt_statuses=None):
        super().__init__()
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.halt_statuses = halt_statuses
        if self.halt_statuses is None:
            self.halt_statuses = []
        self.error_handler = raise_for_status

    def request(self, method, url, timeout=None, max_retries=None, backoff_factor=None, halt_statuses=None, **kwargs):
        # use session defaults when value is not overriden by request
        if timeout is None:
            timeout = self.timeout
        if max_retries is None:
            max_retries = self.max_retries
        if backoff_factor is None:
            backoff_factor = self.backoff_factor

        # merge halt_statuses
        if halt_statuses is None:
            halt_statuses = []
        halt_statuses = self.halt_statuses + halt_statuses

        # mount retry adapter
        retry_strategy = Retry(
            total = max_retries,
            status_forcelist = Range(400, 600, halt_statuses), 
            backoff_factor = backoff_factor,
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount('https://', adapter)
        self.mount('http://', adapter)

        # apply base url if one exists
        if not url.startswith(self.base_url):
            url = f'{self.base_url}{url}'

        response = super().request(method, url, timeout=timeout, **kwargs)

        # raise status code exceptions
        if self.error_handler is not None:
            self.error_handler(response)

        # return the response
        return response

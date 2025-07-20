import json
import logging
import urllib

import pytz
import requests
from saq.configuration.config import get_config_value, get_config_value_as_boolean, get_config_value_as_int
from saq.constants import CONFIG_ELK, CONFIG_ELK_CLUSTER, CONFIG_ELK_ENABLED, CONFIG_ELK_MAX_RESULT_COUNT, CONFIG_ELK_PASSWORD, CONFIG_ELK_RELATIVE_DURATION_AFTER, CONFIG_ELK_RELATIVE_DURATION_BEFORE, CONFIG_ELK_URI, CONFIG_ELK_USERNAME
from saq.modules.base_module import AnalysisModule
from saq.util.time import create_timedelta


class ELKAnalysisModule(AnalysisModule):
    """An analysis module that queries ElasticSearch as part of its analysis."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # for relative time searches, how far back and forward do we go?
        self.earliest_timedelta = create_timedelta(get_config_value(CONFIG_ELK, CONFIG_ELK_RELATIVE_DURATION_BEFORE))
        if "relative_duration_before" in self.config:
            self.earliest_timedelta = create_timedelta(self.config["relative_duration_before"])

        self.latest_timedelta = create_timedelta(get_config_value(CONFIG_ELK, CONFIG_ELK_RELATIVE_DURATION_AFTER))
        if "relative_duration_after" in self.config:
            self.latest_timedelta = create_timedelta(self.config["relative_duration_after"])

        # format the elk search uri with the username and password if it's specified
        if get_config_value(CONFIG_ELK, CONFIG_ELK_USERNAME) and get_config_value(CONFIG_ELK, CONFIG_ELK_PASSWORD):
            # using urlencoding in case username or password has funky characters
            self.elk_uri = "https://{}:{}@{}".format(urllib.parse.quote_plus(get_config_value(CONFIG_ELK, CONFIG_ELK_USERNAME)), 
                                                     urllib.parse.quote_plus(get_config_value(CONFIG_ELK, CONFIG_ELK_PASSWORD)), 
                                                     get_config_value(CONFIG_ELK, CONFIG_ELK_URI))
        else:
            self.elk_uri = "https://{}".format(get_config_value(CONFIG_ELK, CONFIG_ELK_URI))

        # make sure it ends with /
        if not self.elk_uri.endswith('/'):
            self.elk_uri += '/'

        # the maximum number of results we would want
        self.max_result_count = get_config_value_as_int(CONFIG_ELK, CONFIG_ELK_MAX_RESULT_COUNT)
        if "max_result_count" in self.config:
            self.max_result_count = self.config.getint("max_result_count")

        # if we've specified a cluster in the global config then we prefix our index with that cluster
        self.cluster = "" # by default we don't specify the cluster at all
        if get_config_value(CONFIG_ELK, CONFIG_ELK_CLUSTER):
            self.cluster = get_config_value(CONFIG_ELK_CLUSTER)

        # we can also specify the cluster for this specific module
        if "cluster" in self.config:
            self.cluster = self.config["cluster"]

    def search(self, index, query, target=None, earliest=None, latest=None, fields=[], sort=[]):
        """Searches ELK using the given query.
            :param index: The index to search.
            :param query: The query to execute against the index.
            :param target: A datetime to reference if the time span is relative.
            :param earliest: The earliest part of an absolute time span.
            :param latest: The latest part of an absolute time span.
            :param fields: Optional list of fields in include in the results. Defaults to all fields.
            :param sort: Optional list of JSON dicts specifying the sort. Defaults to event_timestamp desc.
            (see https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-sort.html)
            :returns: or None on failure
        """

        # is elk searching enabled?
        if not get_config_value_as_boolean(CONFIG_ELK, CONFIG_ELK_ENABLED):
            logging.warning("analysis module {} enabled but elk is disabled globally".format(self.name))
            return None

        if ( earliest is None and latest is not None ) or ( earliest is not None and latest is None ):
            raise RuntimeError("if you pass an absolute time range to ELKAnalysisModule.search you must "
                             "provide values for both earliest and latest parameters")

        if earliest is None and latest is None: 
            if target is None and self.get_root() is None:
                raise RuntimeError("no time specified for ELKAnalysisModule.search and no root object to pull a time from")

            # if no time is specified then use the insert_date of the root analysis object
            if target is None:
                target = self.get_root().event_time_datetime

            earliest = target - self.earliest_timedelta
            latest = target + self.latest_timedelta

        # if we don't have a timezone set then we assume the timezone is whatever the local system timezone is
        if earliest.tzinfo is None:
            earliest = earliest.astimezone().astimezone(pytz.UTC)

        if latest.tzinfo is None:
            latest = latest.astimezone().astimezone(pytz.UTC)

        # if we did not specify a sort then default to sorting by event_timestamp desc
        if not sort:
            sort = [ { 'event_timestamp': { 'order': 'desc'} } ]

        search_json = {
            'size': self.max_result_count,
            'query': {
                'bool': {
                    'filter': [
                    {
                        'query_string': {
                            'query': query,
                        }
                    },
                    {
                        'range': {
                            '@timestamp': {
                                'format': 'epoch_second',
                                'gte': earliest.timestamp(),
                                'lte': latest.timestamp(),
                            }
                        }
                    },
                    ]
                }
            },
            'sort': sort,
        }

        # are we limiting what fields we get back?
        if fields:
            search_json['_source'] = fields

        # are we specifying a cluster?
        if self.cluster:
            index = '{}:{}'.format(self.cluster, index)

        search_uri = "{}{}/_search".format(self.elk_uri, index)
        search_id = '{} query {} earliest {} latest {}'.format(search_uri, query, earliest, latest)
        logging.debug("executing search {}".format(search_id))

        headers = {'Content-type':'application/json'}
        search_result = requests.get(search_uri, data=json.dumps(search_json), headers=headers, verify=False) # XXX remove verify=False
        if search_result.status_code != 200:
            logging.warning("search failed for {}: {}".format(search_id, search_result.text))
            return None

        json_result = search_result.json()
        logging.debug("search result {}: timed_out {} took {} shards {} clusters {}".format(
                      search_id,
                      json_result['timed_out'],
                      json_result['took'],
                      json_result['_shards'],
                      json_result['_clusters']))

        return json_result
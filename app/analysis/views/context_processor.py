import logging
from uuid import uuid4
from app.blueprints import analysis
from saq.configuration.config import get_config

# additional functions to make available to the templates
@analysis.context_processor
def generic_functions():
    def generate_unique_reference():
        return str(uuid4())

    return { 'generate_unique_reference': generate_unique_reference }

@analysis.context_processor
def send_to_hosts():
    hosts = {}
    try:
        config_keys = [x for x in get_config().keys() if x.startswith('send_to_')]
        hosts = [get_config()[x] for x in config_keys]
    except Exception as e:
        logging.error(f"no hosts properly configured to send to: {e}")

    return dict(send_to_hosts=hosts)

@analysis.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response
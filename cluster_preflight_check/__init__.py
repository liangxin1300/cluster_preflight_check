# Set default logging handler to avoid "no handler found" warnings
import logging
try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('cpc').addHandler(NullHandler())

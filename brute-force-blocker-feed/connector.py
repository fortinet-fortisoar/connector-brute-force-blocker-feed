"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError, Connector
from .operations import operations, _check_health

logger = get_logger('brute-force-blocker-feed')


class BruteForceBlockerFeed(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            # todo let call connector take it from _info
            # now was ingesting it from integration separately
            # changes for fcp/tip specific so it dsnt break on fsr
            if 'connector_name' in kwargs:
                kwargs.pop('connector_name')
            return action(config, params, **kwargs)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def check_health(self, config):
        _check_health(config)

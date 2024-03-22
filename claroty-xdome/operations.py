"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""
import json
from datetime import datetime

import requests
from connectors.core.connector import get_logger, ConnectorError

from .constants import *

logger = get_logger('claroty-xdome')


class ClarotyXDOMEConnector:
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not (self.server_url.startswith('https://') or self.server_url.startswith('http://')):
            self.server_url = 'https://' + self.server_url
        self.server_url = self.server_url.strip('/')
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint, method='GET', data=None, params=None, files=None):
        try:
            url = self.server_url + endpoint
            logger.info('Executing url {}'.format(url))
            headers = {'Authorization': f"Bearer {self.api_key}", 'Content-Type': 'application/json'}

            # CURL UTILS CODE
            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")

            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                logger.info('Successfully got response for url {}'.format(url))
                if method.upper() == 'DELETE':
                    return response
                else:
                    return response.json()
            elif response.status_code == 400:
                error_response = response.json()
                error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            elif response.status_code == 401:
                error_response = response.json()
                if error_response.get('error'):
                    error_description = error_response['error']
                else:
                    error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            elif response.status_code == 404:
                error_response = response.json()
                error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            else:
                logger.error(response.json())
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))
        raise ConnectorError(response.text)


def _check_health(config):
    try:
        tg = ClarotyXDOMEConnector(config)
        endpoint = '/api/v1/alerts'
        response = tg.make_request(endpoint=endpoint, method='POST', data=json.dumps({"limit": 1, "fields": [
            "id",
            "alert_name"
        ]}))
        if response:
            logger.info("Claroty XDOME Connector Available")
            return True
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def get_alerts(config: dict, params: dict):
    try:
        cx = ClarotyXDOMEConnector(config)
        params = _build_payload(params)
        endpoint = '/api/v1/alerts'
        operands_list = _build_filter_query(params, alert_fields_to_check)
        if len(operands_list) > 0:
            params.update({"filter_by": {"operation": "and", "operands": operands_list}})

        return cx.make_request(endpoint=endpoint, method='POST', data=json.dumps(params))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def get_devices(config: dict, params: dict):
    try:
        cx = ClarotyXDOMEConnector(config)
        params = _build_payload(params)
        endpoint = '/api/v1/devices'
        operands_list = _build_filter_query(params, device_fields_to_check)
        if len(operands_list) > 0:
            params.update({"filter_by": {"operation": "and", "operands": operands_list}})

        return cx.make_request(endpoint=endpoint, method='POST', data=json.dumps(params))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def get_ot_events(config: dict, params: dict):
    try:
        cx = ClarotyXDOMEConnector(config)
        params = _build_payload(params)
        endpoint = '/api/v1/ot_activity_events'
        operands_list = _build_filter_query(params, ot_events_fields_to_check)
        if len(operands_list) > 0:
            params.update({"filter_by": {"operation": "and", "operands": operands_list}})

        return cx.make_request(endpoint=endpoint, method='POST', data=json.dumps(params))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def get_vulnerabilities(config: dict, params: dict):
    try:
        cx = ClarotyXDOMEConnector(config)
        params = _build_payload(params)
        endpoint = '/api/v1/vulnerabilities'
        operands_list = _build_filter_query(params, vulnerability_fields_to_check)
        if len(operands_list) > 0:
            params.update({"filter_by": {"operation": "and", "operands": operands_list}})

        return cx.make_request(endpoint=endpoint, method='POST', data=json.dumps(params))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def execute_generic_claroty_api(config: dict, params: dict):
    try:
        cx = ClarotyXDOMEConnector(config)
        params = _build_payload(params)
        endpoint = params.pop('endpoint')
        return cx.make_request(endpoint=endpoint, method='POST', data=json.dumps(params.get('parameters')))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def _build_filter_query(params: dict, field_to_check: list) -> list:
    operands = []
    if params.get('filter_by') is not None:
        operands.extend(params.pop('filter_by'))

    for p in field_to_check:
        if params.get(p) is not None:
            logger.debug(f"Field is {p} and its value is {params.get(p)}")
            if device_format_dict.get(p) is not None:
                value = [device_format_dict.get(p).get(x.strip()) for x in params.pop(p)]
            else:
                if all(isinstance(item, int) for item in params.get(p)):
                    value = params.pop(p)
                elif type(params.get(p)) is list:
                    value = [x.strip() for x in params.pop(p)]
                elif type(params.get(p)) is int:
                    value = [params.pop(p)]
                else:
                    value = [x.strip() for x in params.pop(p).split(",")]
            obj = {"field": p, "operation": "in", "value": value}
            operands.append(obj)
            logger.info(f"Operands : {operands}")

    if params.get('before_detected_time') is not None:
        operands = _convert_epoch_to_utc(params.pop('before_detected_time'),
                                         {"field_name": "detected_time", "operation": "less_or_equal"}, operands)

    if params.get('after_detected_time') is not None:
        operands = _convert_epoch_to_utc(params.pop('after_detected_time'),
                                         {"field_name": "detected_time", "operation": "greater_or_equal"}, operands)

    if params.get('cvss_v3_score') is not None:
        operands.append(
            {"field": "cvss_v3_score", "operation": "greater_or_equal", "value": params.pop('cvss_v3_score')})

    return operands


def _convert_epoch_to_utc(time: int, param_type: dict, operands: list) -> list:
    if type(time) is int:
        datetime_object = datetime.fromtimestamp(time)
        time = datetime_object.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    operands.append({"field": param_type.get("field_name"), "operation": param_type.get("operation"), "value": time})
    return operands


def _build_payload(params: dict) -> dict:
    if params.get('fields') is not None:
        params.update(params.pop('fields'))

    if params.get('sort_by') is not None:
        if type(params.get('sort_by')) == dict:
            params.update({"sort_by": [params.get('sort_by')]})

    if params.get('filter_by') is not None:
        if type(params.get('filter_by')) == dict:
            update_operands = [params.pop('filter_by')]
            params.update({"filter_by": update_operands})

    return {key: val for key, val in params.items() if val is not None and val != ''}


operations = {
    "get_alerts": get_alerts,
    "get_devices": get_devices,
    "get_ot_events": get_ot_events,
    "execute_generic_claroty_api": execute_generic_claroty_api,
    "get_vulnerabilities": get_vulnerabilities
}
#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from pfsensefw_consts import *
import requests
import json
# import pudb
from bs4 import BeautifulSoup


stat_block_message = "Block all request from IP: "


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class PfsensefwConnector(BaseConnector):

    def __init__(self):
        super(PfsensefwConnector, self).__init__()
        self._state = None
        self._base_url = None
        self._client_id = None
        self._client_token = None

    def _validate_subnet_mask(self, subnet):
        if subnet.isnumeric() and 1 <= int(subnet) <= 32:
            return subnet

        number_list = subnet.split(".")
        if len(number_list) == 4:
            for n in number_list:
                if int(n) < 0 or int(n) > 255:
                    return None
            return str(sum(bin(int(n)).count('1') for n in number_list))
        return None

    def _validate_src_ip(self, src_ip, subnet):
        num_list = src_ip.split(".")
        ip_range = ((int(subnet) // 8 + 1, int(subnet) // 8)[int(subnet) % 8 == 0]) - 1
        for n in range(0, 4):
            if n > ip_range:
                num_list[n] = "0"
        return ".".join(num_list)

    def _get_json_data(self, src_ip, descr, subnet=""):
        return {
                "client-id": self._client_id,
                "client-token": self._client_token,
                "type": "block",
                "interface": "wan",
                "ipprotocol": "inet",
                "protocol": "any",
                "src": (src_ip + "/" + subnet, src_ip)[subnet == ""],
                "srcport": "any",
                "dst": "any",
                "dstport": "any",
                "descr": descr,
                "top": False
            }

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"
        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)
        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        if not r.text:
            return self._process_empty_response(r, action_result)
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", json_data=None, is_validate_request=False, **kwargs):
        resp_json = None
        url = "https://" + self._base_url + endpoint
        try:
            if method.lower() == "get":
                r = requests.get(url, json_data, verify=False)
            elif method.lower() == "post":
                r = requests.post(url, json=json_data, verify=False)
            elif method.lower() == "delete":
                r = requests.delete(url, data=json.dumps(json_data), verify=False)
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )
        if is_validate_request:
            return None, r
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        data = {
            "client-id": self._client_id,
            "client-token": self._client_token
        }
        self.save_progress("Connecting to endpoint")
        ret_val, response = self._make_rest_call(
            '/api/v1/system/arp', action_result, json_data=data
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_ip(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        src_ip = param['src_ip']
        data = {
            "client-id": self._client_id,
            "client-token": self._client_token,
            "source__address": src_ip
        }
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/rule', action_result, json_data=data, is_validate_request=True
        )
        if src_ip in response.text:
            for k, v in json.loads(response.text)["data"].items():
                data = {
                    "client-id": self._client_id,
                    "client-token": self._client_token,
                    "tracker": v["tracker"]
                }
                ret_val, response = self._make_rest_call(
                    '/api/v1/firewall/rule', action_result, method="delete", json_data=data
                )
                if ret_val is False:
                    break
                action_result.add_data(response)
        if phantom.is_fail(ret_val):
            return (action_result.get_status(),
                    action_result.set_status(phantom.APP_ERROR, "No Rule for IP:" + src_ip + " founded")
                    )[ret_val is None]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_ip(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        src_ip = param['src_ip']
        data = {
            "client-id": self._client_id,
            "client-token": self._client_token,
            "source__address": src_ip
        }
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/rule', action_result, json_data=data, is_validate_request=True
        )
        if src_ip not in response.text:
            data = self._get_json_data(src_ip, stat_block_message + src_ip + " to out side")
            ret_val, response = self._make_rest_call(
                '/api/v1/firewall/rule', action_result, method="post", json_data=data
            )
        if phantom.is_fail(ret_val):
            return (action_result.get_status(),
                    action_result.set_status(phantom.APP_ERROR, "Rule for IP:" + src_ip + " already existed")
                    )[ret_val is None]
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_show_blocked_ip(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        data = {
            "client-id": self._client_id,
            "client-token": self._client_token,
            "type": "block",
            "descr__startswith": stat_block_message
        }
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/rule', action_result, json_data=data
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_a_network(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        subnet = self._validate_subnet_mask(param['subnet'])
        if subnet is None:
            return action_result.set_status(phantom.APP_ERROR, "Fail to validate subnet " + param['subnet'])
        src_ip = self._validate_src_ip(param['src_ip'], subnet)
        data = {
            "client-id": self._client_id,
            "client-token": self._client_token,
            "source__address__contains": "/",
            "source__address__startswith": src_ip,
        }
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/rule', action_result, json_data=data, is_validate_request=True
        )
        if src_ip not in response.text:
            data = self._get_json_data(src_ip, "Block all request from " + src_ip + "/" + subnet + " to out side", subnet)
            ret_val, response = self._make_rest_call(
                '/api/v1/firewall/rule', action_result, method="post", json_data=data
            )
        if phantom.is_fail(ret_val):
            return (action_result.get_status(),
                    action_result.set_status(phantom.APP_ERROR, "Rule for " + src_ip + "/" + subnet + " already existed")
                    )[ret_val is None]
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_a_network(self, param):
        # pudb.set_trace()
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        subnet = self._validate_subnet_mask(param['subnet'])
        if subnet is None:
            return action_result.set_status(phantom.APP_ERROR, "Fail to validate subnet " + param['subnet'])
        src_ip = self._validate_src_ip(param['src_ip'], subnet)
        data = {
            "client-id": self._client_id,
            "client-token": self._client_token,
            "source__address": src_ip + "/" + subnet,
        }
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/rule', action_result, json_data=data, is_validate_request=True
        )

        if src_ip in response.text:
            for k, v in json.loads(response.text)["data"].items():
                data = {
                    "client-id": self._client_id,
                    "client-token": self._client_token,
                    "tracker": v["tracker"]
                }
                ret_val, response = self._make_rest_call(
                    '/api/v1/firewall/rule', action_result, method="delete", json_data=data
                )
                if ret_val is False:
                    break
                action_result.add_data(response)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(),
                    action_result.set_status(phantom.APP_ERROR, "No Rule for " + src_ip + "/" + subnet + " founded")
                    )[ret_val is None]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_show_blocked_network(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = {
            "client-id": self._client_id,
            "client-token": self._client_token,
            "type": "block",
            "source__address__contains": "/",
        }
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/rule', action_result, json_data=data
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_apply_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call(
            '/api/v1/firewall/apply', action_result, method="post", is_validate_request=True
        )
        return (action_result.set_status(phantom.APP_SUCCESS),
                action_result.set_status(phantom.APP_ERROR, "Fail to apply changed rules")
                )[ret_val is None]

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'unblock_ip':
            ret_val = self._handle_unblock_ip(param)

        elif action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)

        elif action_id == 'show_blocked_ip':
            ret_val = self._handle_show_blocked_ip(param)

        elif action_id == 'block_a_network':
            ret_val = self._handle_block_a_network(param)

        elif action_id == 'unblock_a_network':
            ret_val = self._handle_unblock_a_network(param)

        elif action_id == 'show_blocked_network':
            ret_val = self._handle_show_blocked_network(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config.get('base_url')
        self._client_id = config.get('client_id')
        self._client_token = config.get('client_token')
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()
    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = PfsensefwConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PfsensefwConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()

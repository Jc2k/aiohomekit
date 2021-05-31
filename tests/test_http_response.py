#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json

from aiohomekit.http.response import HttpResponse


def parse(data):
    response = HttpResponse()
    for i in range(0, len(data)):
        response.parse(data[i])
        if response.is_read_completely():
            break

    assert response.is_read_completely()

    return response


def test_example1():
    parts = [
        bytearray(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/hap+json\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        ),
        bytearray(
            b'5f\r\n{"characteristics":[{"aid":1,"iid":10,"value":35},'
            b'{"aid":1,"iid":13,"value":36.0999984741211}]}\r\n'
        ),
        bytearray(b"0\r\n\r\n"),
    ]
    res = parse(parts)
    assert res.code == 200
    assert res.get_http_name() == "HTTP"
    assert (
        res.body
        == b'{"characteristics":[{"aid":1,"iid":10,"value":35},{"aid":1,"iid":13,"value":36.0999984741211}]}'
    )
    json.loads(res.body.decode())


def test_example2():
    parts = [
        bytearray(
            b"EVENT/1.0 200 OK\r\nContent-Type: application/hap+json\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        bytearray(
            b'5f\r\n{"characteristics":[{"aid":1,"iid":10,"value":35},'
            b'{"aid":1,"iid":13,"value":33.2000007629395}]}\r\n'
        ),
        bytearray(b"0\r\n\r\n"),
    ]
    res = parse(parts)
    assert res.code == 200
    assert res.get_http_name() == "EVENT"
    assert (
        res.body
        == b'{"characteristics":[{"aid":1,"iid":10,"value":35},{"aid":1,"iid":13,"value":33.2000007629395}]}'
    )
    j = json.loads(res.body.decode())
    assert j["characteristics"][1]["value"] == 33.2000007629395


def test_example3():
    parts = [
        bytearray(
            b"HTTP/1.1 200 OK\r\nServer: BaseHTTP/0.6 Python/3.5.3\r\nDate: Mon, 04 Jun 2018 20:06:06 GMT\r\n"
            b'Content-Type: application/hap+json\r\nContent-Length: 3740\r\n\r\n{"accessories": [{"services": '
            b'[{"characteristics": [{"maxLen": 64, "type": "00000014-0000-1000-8000-0026BB765291", "format": "bool", '
            b'"description": "Identify", "perms": ["pw"], "maxDataLen": 2097152, "iid": 3}, {"maxLen": 64, "type": '
            b'"00000020-0000-1000-8000-0026BB765291", "format": "string", "description": "Manufacturer", "perms": '
            b'["pr"], "maxDataLen": 2097152, "value": "lusiardi.de", "iid": 4}, {"maxLen": 64, "type": '
            b'"00000021-0000-1000-8000-0026BB765291", "format": "string", "description": "Model", "perms": ["pr"], '
            b'"maxDataLen": 2097152, "value": "Demoserver", "iid": 5}, {"maxLen": 64, "type": '
            b'"00000023-0000-1000-8000-0026BB765291", "format": "string", "description": "Name", "perms": ["pr"], '
            b'"maxDataLen": 2097152, "value": "Notifier", "iid": 6}, {"maxLen": 64, "type": '
            b'"00000030-0000-1000-8000-0026BB765291", "format": "string", "description": "Serial Number", "'
        ),
        bytearray(
            b'perms": ["pr"], "maxDataLen": 2097152, "value": "0001", "iid": 7}, {"maxLen": 64, "type": '
            b'"00000052-0000-1000-8000-0026BB765291", "format": "string", "description": "Firmware Revision",'
            b' "perms": ["pr"], "maxDataLen": 2097152, "value": "0.1", "iid": 8}], "type": '
            b'"0000003E-0000-1000-8000-0026BB765291", "iid": 2}, {"characteristics": [{"maxLen": 64, "type": '
            b'"00000025-0000-1000-8000-0026BB765291", "format": "bool", "description": '
            b'"Switch state (on/off)", "perms": ["pw", "pr", "ev"], "maxDataLen": 2097152, "value": false, '
            b'"iid": 10}, {"maxDataLen": 2097152, "minStep": 1, "description": "Brightness in percent", '
            b'"unit": "percentage", "minValue": 0, "perms": ["pr", "pw", "ev"], "maxValue": 100, "maxLen": '
            b'64, "type": "00000008-0000-1000-8000-0026BB765291", "format": "int", "value": 0, "iid": 11}, '
            b'{"maxDataLen": 2097152, "minStep": 1, "description": "Hue in arc degrees", "unit": '
            b'"arcdegrees", "minValue": 0, "perms": ["pr", "pw", "ev"], "maxValue": 360, "maxLen": 64, '
            b'"type": "00000013-0000-1000-8000-0026BB765291", "form'
        ),
        bytearray(
            b'at": "float", "value": 0, "iid": 12}, {"maxDataLen": 2097152, "minStep": 1, "description": '
            b'"Saturation in percent", "unit": "percentage", "minValue": 0, "perms": ["pr", "pw", "ev"], '
            b'"maxValue": 100, "maxLen": 64, "type": "0000002F-0000-1000-8000-0026BB765291", "format": '
            b'"float", "value": 0, "iid": 13}], "type": "00000043-0000-1000-8000-0026BB765291", "iid": 9}], '
            b'"aid": 1}, {"services": [{"characteristics": [{"maxLen": 64, "type": '
            b'"00000014-0000-1000-8000-0026BB765291", "format": "bool", "description": "Identify", "perms": '
            b'["pw"], "maxDataLen": 2097152, "iid": 16}, {"maxLen": 64, "type": '
            b'"00000020-0000-1000-8000-0026BB765291", "format": "string", "description": "Manufacturer", '
            b'"perms": ["pr"], "maxDataLen": 2097152, "value": "lusiardi.de", "iid": 17}, {"maxLen": 64, '
            b'"type": "00000021-0000-1000-8000-0026BB765291", "format": "string", "description": "Model", '
            b'"perms": ["pr"], "maxDataLen": 2097152, "value": "Demoserver", "iid": 18}, {"maxLen": 64, '
            b'"type": "00000023-0000-1000-8000-0026BB765291", "format": "string"'
        ),
        bytearray(
            b', "description": "Name", "perms": ["pr"], "maxDataLen": 2097152, "value": "Dummy", "iid": 19},'
            b' {"maxLen": 64, "type": "00000030-0000-1000-8000-0026BB765291", "format": "string", '
            b'"description": "Serial Number", "perms": ["pr"], "maxDataLen": 2097152, "value": "0001", '
            b'"iid": 20}, {"maxLen": 64, "type": "00000052-0000-1000-8000-0026BB765291", "format": "string",'
            b' "description": "Firmware Revision", "perms": ["pr"], "maxDataLen": 2097152, "value": "0.1", '
            b'"iid": 21}], "type": "0000003E-0000-1000-8000-0026BB765291", "iid": 15}, {"characteristics": '
            b'[{"perms": ["pw", "pr"], "maxLen": 64, "minValue": 2, "type": '
            b'"00000023-0000-1000-8000-0026BB765291", "format": "float", "description": "Test", "minStep":'
            b' 0.25, "maxDataLen": 2097152, "iid": 23}], "type": "00000040-0000-1000-8000-0026BB765291", '
            b'"iid": 22}], "aid": 14}]}'
        ),
    ]
    res = parse(parts)
    assert res.code == 200
    assert res.get_http_name() == "HTTP"
    json.loads(res.body.decode())


def test_example4():
    parts = [
        bytearray(
            b"HTTP/1.1 200 OK\r\nServer: BaseHTTP/0.6 Python/3.5.3\r\nDate: Mon, 04 Jun 2018 21:38:07 "
            b'GMT\r\nContent-Type: application/hap+json\r\nContent-Length: 3740\r\n\r\n{"accessories": '
            b'[{"aid": 1, "services": [{"type": "0000003E-0000-1000-8000-0026BB765291", '
            b'"characteristics": [{"format": "bool", "maxLen": 64, "iid": 3, "description": "Identify", '
            b'"perms": ["pw"], "type": "00000014-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, '
            b'{"value": "lusiardi.de", "format": "string", "maxLen": 64, "iid": 4, "description": '
            b'"Manufacturer", "perms": ["pr"], "type": "00000020-0000-1000-8000-0026BB765291", '
            b'"maxDataLen": 2097152}, {"value": "Demoserver", "format": "string", "maxLen": 64, '
            b'"iid": 5, "description": "Model", "perms": ["pr"], "type": '
            b'"00000021-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "Notifier", '
            b'"format": "string", "maxLen": 64, "iid": 6, "description": "Name", "perms": ["pr"], '
            b'"type": "00000023-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "0001", '
            b'"format": "string", "maxLen": 64, "iid":'
        ),
        bytearray(
            b' 7, "description": "Serial Number", "perms": ["pr"], "type": '
            b'"00000030-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "0.1", "format": '
            b'"string", "maxLen": 64, "iid": 8, "description": "Firmware Revision", "perms": ["pr"], "type": '
            b'"00000052-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}], "iid": 2}, {"type": '
            b'"00000043-0000-1000-8000-0026BB765291", "characteristics": [{"value": false, "format": "bool", '
            b'"maxLen": 64, "iid": 10, "description": "Switch state (on/off)", "perms": ["pw", "pr", "ev"], '
            b'"type": "00000025-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"maxValue": 100, '
            b'"format": "int", "minStep": 1, "description": "Brightness in percent", "perms": ["pr", "pw", '
            b'"ev"], "maxDataLen": 2097152, "type": "00000008-0000-1000-8000-0026BB765291", "maxLen": 64, '
            b'"iid": 11, "value": 0, "unit": "percentage", "minValue": 0}, {"maxValue": 360, "format": '
            b'"float", "minStep": 1, "description": "Hue in arc degrees", "perms": ["pr", "pw", "ev"], '
            b'"maxDataLen": 2097152, "type": "00000013-0000-1000'
        ),
        bytearray(
            b'-8000-0026BB765291", "maxLen": 64, "iid": 12, "value": 0, "unit": "arcdegrees", "minValue": 0},'
            b' {"maxValue": 100, "format": "float", "minStep": 1, "description": "Saturation in percent", '
            b'"perms": ["pr", "pw", "ev"], "maxDataLen": 2097152, "type": '
            b'"0000002F-0000-1000-8000-0026BB765291", "maxLen": 64, "iid": 13, "value": 0, "unit": '
            b'"percentage", "minValue": 0}], "iid": 9}]}, {"aid": 14, "services": [{"type": '
            b'"0000003E-0000-1000-8000-0026BB765291", "characteristics": [{"format": "bool", "maxLen": 64, '
            b'"iid": 16, "description": "Identify", "perms": ["pw"], "type": '
            b'"00000014-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "lusiardi.de", '
            b'"format": "string", "maxLen": 64, "iid": 17, "description": "Manufacturer", "perms": ["pr"], '
            b'"type": "00000020-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "Demoserver",'
            b' "format": "string", "maxLen": 64, "iid": 18, "description": "Model", "perms": ["pr"], "type": '
            b'"00000021-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "Dummy", "fo'
        ),
        bytearray(
            b'rmat": "string", "maxLen": 64, "iid": 19, "description": "Name", "perms": ["pr"], "type": '
            b'"00000023-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "0001", "format": '
            b'"string", "maxLen": 64, "iid": 20, "description": "Serial Number", "perms": ["pr"], "type": '
            b'"00000030-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}, {"value": "0.1", "format": '
            b'"string", "maxLen": 64, "iid": 21, "description": "Firmware Revision", "perms": ["pr"], '
            b'"type": "00000052-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}], "iid": 15}, {"type": '
            b'"00000040-0000-1000-8000-0026BB765291", "characteristics": [{"minStep": 0.25, "format": '
            b'"float", "maxLen": 64, "iid": 23, "description": "Test", "perms": ["pw", "pr"], "minValue": 2, '
            b'"type": "00000023-0000-1000-8000-0026BB765291", "maxDataLen": 2097152}], "iid": 22}]}]}'
        ),
    ]
    res = parse(parts)
    assert res.code == 200
    assert res.get_http_name() == "HTTP"
    json.loads(res.body.decode())


def test_example_lines():
    parts = [
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: application/hap+json\r\n",
        b"Content-Length: 95\r\n",
        b"Connection: keep-alive\r\n",
        b"\r\n",
        b'{"characteristics":[{"aid":1,"iid":10,"value":35},',
        b'{"aid":1,"iid":13,"value":36.0999984741211}]}',
    ]
    res = parse(parts)
    assert res.code == 200
    assert res.get_http_name() == "HTTP"
    assert (
        res.body
        == b'{"characteristics":[{"aid":1,"iid":10,"value":35},{"aid":1,"iid":13,"value":36.0999984741211}]}'
    )
    json.loads(res.body.decode())


def test_example_204():
    res = parse([b"HTTP/1.1 204 No content\r\n\r\n"])
    assert res.code == 204
    assert res.get_http_name() == "HTTP"
    assert res.body == b""
    assert res.headers == []


def test_example_470():
    res = parse([b"HTTP/1.1 470 Connection Authorization Required\r\n\r\n"])
    assert res.code == 470
    assert res.get_http_name() == "HTTP"
    assert res.body == b""
    assert res.headers == []


def test_example_multi_status():
    res = parse(
        [
            (
                b"HTTP/1.1 207 Multi-Status\r\n"
                b"Content-Type: application/hap+json\r\n"
                b"Date: Sun, 29 Mar 2020 21:58:41 GMT\r\n"
                b"Connection: keep-alive\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n"
                b"33\r\n"
                b'{"characteristics":[{"aid":2,"iid":10,"status":0}]}\r\n'
                b"0\r\n"
                b"\r\n"
            )
        ]
    )
    assert res.code == 207
    assert res.body == b'{"characteristics":[{"aid":2,"iid":10,"status":0}]}'


def test_example_multi_status_2():
    res = parse(
        [
            (
                b"HTTP/1.1 207 Multi-Status\r\n"
                b"Content-Type: application/hap+json\r\n"
                b"Date: Sun, 29 Mar 2020 21:58:24 GMT\r\n"
                b"Connection: keep-alive\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n"
                b"40\r\n"
                b'{"characteristics":[{"aid":2,"iid":10,"value":true,"status":0}]}\r\n'
                b"0\r\n"
                b"\r\n"
            )
        ]
    )
    assert res.code == 207
    assert (
        res.body == b'{"characteristics":[{"aid":2,"iid":10,"value":true,"status":0}]}'
    )


def test_example_multi_status_3():
    """
    Test that 2 payloads arriving in same packet works.

    https://github.com/Jc2k/aiohomekit/issues/1
    """
    res = parse(
        [
            (
                b"HTTP/1.1 207 Multi-Status\r\n"
                b"Content-Type: application/hap+json\r\n"
                b"Date: Sun, 29 Mar 2020 21:57:54 GMT\r\n"
                b"Connection: keep-alive\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n"
                b"33\r\n"
                b'{"characteristics":[{"aid":2,"iid":10,"status":0}]}\r\n'
                b"0\r\n"
                b"\r\n"
                b"HTTP/1.1 207 Multi-Status\r\n"
                b"Content-Type: application/hap+json"
                b"\r\nDate: Sun, 29 Mar 2020 21:57:54 GMT\r\n"
                b"Connection: keep-alive\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n"
                b"33\r\n"
                b'{"characteristics":[{"aid":2,"iid":10,"status":0}]}\r\n'
                b"0\r\n"
                b"\r\n"
            )
        ]
    )
    assert res.code == 207


def test_newline_in_payload():
    parts = [
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: application/hap+json\r\n",
        b"Content-Length: 97\r\n",
        b"Connection: keep-alive\r\n",
        b"\r\n",
        b'{"characteristics":[{"aid":1,"iid":10,"value":35},\r\n',
        b'{"aid":1,"iid":13,"value":36.0999984741211}]}',
    ]
    res = parse(parts)
    assert res.code == 200
    assert res.get_http_name() == "HTTP"
    assert (
        res.body
        == b'{"characteristics":[{"aid":1,"iid":10,"value":35},\r\n{"aid":1,"iid":13,"value":36.0999984741211}]}'
    )

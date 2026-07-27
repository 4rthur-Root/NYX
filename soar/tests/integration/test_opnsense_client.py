from unittest.mock import Mock

import pytest
import requests

from soar.integrations import OPNsenseClient


SEARCH_RESPONSE = {
    "rows": [
        {
            "name": "soar_blocklist",
            "type": "host",
            "content": "10.0.1.50\n10.0.1.51",
            "current_items": "2",
        },
    ],
    "rowCount": 1,
    "total": 1,
    "current": 1,
}

SEARCH_RESPONSE_EMPTY = {
    "rows": [
        {
            "name": "soar_blocklist",
            "type": "host",
            "content": "",
            "current_items": "0",
        },
    ],
    "rowCount": 1,
    "total": 1,
    "current": 1,
}

IMPORT_OK = {"existing": 1, "new": 0, "status": "ok"}
IMPORT_FAIL = {"existing": 0, "new": 0, "status": "failed"}


@pytest.fixture
def client():
    return OPNsenseClient()


def _ok_response(json_data=None):
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = json_data or {}
    return mock


class TestBlockIp:
    def test_block_success(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response(SEARCH_RESPONSE_EMPTY),
        )
        mocker.patch(
            "requests.post",
            side_effect=[
                _ok_response(IMPORT_OK),
                _ok_response(),
            ],
        )

        result = client.block_ip("10.0.1.50")

        assert result.api_status_code == 200
        assert result.retry_count == 1
        assert result.blocked_ip == "10.0.1.50"

    def test_block_already_blocked(self, client, mocker):
        mocker.patch.object(client, "list_blocked", return_value=["10.0.1.50"])

        result = client.block_ip("10.0.1.50")

        assert result.api_status_code == 200
        assert result.retry_count == 1

    def test_block_retries_on_import_failure(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response(SEARCH_RESPONSE_EMPTY),
        )
        mocker.patch(
            "requests.post",
            return_value=_ok_response(IMPORT_FAIL),
        )

        result = client.block_ip("10.0.1.50")

        assert result.api_status_code == 0
        assert result.retry_count == 3

    def test_block_retries_on_network_error(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response(SEARCH_RESPONSE_EMPTY),
        )
        mocker.patch(
            "requests.post",
            side_effect=requests.ConnectionError("Timeout"),
        )

        result = client.block_ip("10.0.1.50")

        assert result.api_status_code == 0
        assert result.retry_count == 3


class TestUnblockIp:
    def test_unblock_success(self, client, mocker):
        mocker.patch.object(
            client, "list_blocked", return_value=["10.0.1.50", "10.0.1.51"]
        )
        mocker.patch(
            "requests.post",
            side_effect=[
                _ok_response(IMPORT_OK),
                _ok_response(),
            ],
        )

        result = client.unblock_ip("10.0.1.50")

        assert result.api_status_code == 200
        assert result.retry_count == 1

    def test_unblock_not_blocked(self, client, mocker):
        mocker.patch.object(client, "list_blocked", return_value=[])

        result = client.unblock_ip("10.0.1.50")

        assert result.api_status_code == 200
        assert result.retry_count == 1

    def test_unblock_retries_on_failure(self, client, mocker):
        mocker.patch.object(
            client, "list_blocked", return_value=["10.0.1.50"]
        )
        mocker.patch(
            "requests.post",
            return_value=_ok_response(IMPORT_FAIL),
        )

        result = client.unblock_ip("10.0.1.50")

        assert result.api_status_code == 0
        assert result.retry_count == 3


class TestListBlocked:
    def test_list_returns_ips(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response(SEARCH_RESPONSE),
        )

        blocked = client.list_blocked()

        assert blocked == ["10.0.1.50", "10.0.1.51"]

    def test_list_empty_when_no_content(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response(SEARCH_RESPONSE_EMPTY),
        )

        assert client.list_blocked() == []

    def test_list_returns_empty_on_network_error(self, client, mocker):
        mocker.patch(
            "requests.get",
            side_effect=requests.ConnectionError("Timeout"),
        )

        assert client.list_blocked() == []


class TestIsAlreadyBlocked:
    def test_returns_true_when_blocked(self, client, mocker):
        mocker.patch.object(client, "list_blocked", return_value=["10.0.1.50"])

        assert client.is_already_blocked("10.0.1.50") is True

    def test_returns_false_when_not_blocked(self, client, mocker):
        mocker.patch.object(client, "list_blocked", return_value=[])

        assert client.is_already_blocked("10.0.1.99") is False

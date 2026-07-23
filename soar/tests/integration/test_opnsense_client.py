from unittest.mock import Mock

import pytest
import requests

from soar.integrations import OPNsenseClient


MOCK_ALIAS_CONTENT = "10.0.1.50\n10.0.1.51\n"


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
        mocker.patch("requests.post", return_value=_ok_response())
        mocker.patch.object(client, "_apply", return_value=True)

        result = client.block_ip("10.0.1.50")

        assert result.api_status_code == 200
        assert result.retry_count == 1
        assert result.blocked_ip == "10.0.1.50"

    def test_block_retries_on_failure(self, client, mocker):
        mock_post = mocker.patch("requests.post", return_value=Mock(status_code=500))
        mocker.patch.object(client, "_apply", return_value=True)

        result = client.block_ip("10.0.1.50")

        assert mock_post.call_count == 3
        assert result.api_status_code == 500
        assert result.retry_count == 3

    def test_block_retries_on_network_error(self, client, mocker):
        mock_post = mocker.patch(
            "requests.post",
            side_effect=requests.ConnectionError("Timeout"),
        )

        result = client.block_ip("10.0.1.50")

        assert mock_post.call_count == 3
        assert result.api_status_code == 0
        assert result.retry_count == 3


class TestUnblockIp:
    def test_unblock_success(self, client, mocker):
        mocker.patch("requests.post", return_value=_ok_response())
        mocker.patch.object(client, "_apply", return_value=True)

        result = client.unblock_ip("10.0.1.50")

        assert result.api_status_code == 200
        assert result.retry_count == 1


class TestListBlocked:
    def test_list_returns_ips(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response({"alias": {"content": MOCK_ALIAS_CONTENT}}),
        )

        blocked = client.list_blocked()

        assert blocked == ["10.0.1.50", "10.0.1.51"]

    def test_list_empty_when_no_content(self, client, mocker):
        mocker.patch(
            "requests.get",
            return_value=_ok_response({"alias": {"content": ""}}),
        )

        assert client.list_blocked() == []

    def test_list_returns_empty_on_error(self, client, mocker):
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

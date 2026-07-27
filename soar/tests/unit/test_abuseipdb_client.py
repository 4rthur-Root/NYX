import pytest
import requests

from soar.integrations import AbuseIPDBClient


MOCK_API_RESPONSE = {
    "data": {
        "ipAddress": "10.0.1.50",
        "abuseConfidenceScore": 95,
        "countryCode": "TG",
        "isp": "ISP du lab",
        "domain": "lab.local",
        "totalReports": 42,
        "lastReportedAt": "2026-07-01T00:00:00+00:00",
    }
}


@pytest.fixture
def client():
    return AbuseIPDBClient()


class TestFromCache:
    def test_returns_from_cache_if_present(self, client):
        client._cache.set("10.0.1.50", 85, ttl_seconds=60)
        result = client.get_reputation("10.0.1.50")
        assert result.source == "cache"
        assert result.abuseipdb_score == 85
        assert result.fallback_used is False


class TestFromApi:
    def test_returns_from_api_on_cache_miss(self, client, mocker):
        mocker.patch("requests.get", return_value=mocker.Mock(
            status_code=200,
            json=lambda: MOCK_API_RESPONSE,
            raise_for_status=lambda: None,
        ))
        result = client.get_reputation("10.0.1.50")
        assert result.source == "abuseipdb"
        assert result.abuseipdb_score == 95
        assert result.country_code == "TG"
        assert result.isp == "ISP du lab"
        assert result.fallback_used is False

    def test_api_result_is_cached(self, client, mocker):
        mocker.patch("requests.get", return_value=mocker.Mock(
            status_code=200,
            json=lambda: MOCK_API_RESPONSE,
            raise_for_status=lambda: None,
        ))
        result1 = client.get_reputation("10.0.1.50")
        result2 = client.get_reputation("10.0.1.50")
        assert result1.source == "abuseipdb"
        assert result2.source == "cache"
        assert requests.get.call_count == 1


class TestCircuitBreaker:
    def test_opens_after_3_failures(self, client, mocker):
        mocker.patch("requests.get", side_effect=requests.ConnectionError("Timeout"))

        for _ in range(3):
            result = client.get_reputation("10.0.1.50")
            assert result.source == "unavailable"

        assert client._consecutive_failures == 3
        assert client._circuit_open_until > 0

    def test_returns_fallback_while_circuit_open(self, client, mocker):
        client._circuit_open_until = 9999999999
        client._consecutive_failures = 3

        mock_get = mocker.patch("requests.get")
        result = client.get_reputation("10.0.1.50")

        mock_get.assert_not_called()
        assert result.source == "unavailable"
        assert result.abuseipdb_score is not None


class TestFallbackList:
    def test_uses_fallback_for_known_ip(self, client, mocker):
        client._fallback["10.0.1.99"] = 100

        mocker.patch("requests.get", side_effect=requests.ConnectionError("Timeout"))
        result = client.get_reputation("10.0.1.99")

        assert result.source == "unavailable"
        assert result.abuseipdb_score == 100
        assert result.fallback_used is True

    def test_default_score_50_for_unknown_ip(self, client, mocker):
        mocker.patch("requests.get", side_effect=requests.ConnectionError("Timeout"))
        result = client.get_reputation("99.99.99.99")

        assert result.source == "unavailable"
        assert result.abuseipdb_score == 50
        assert result.fallback_used is True

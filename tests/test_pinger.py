import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import ClientSession

from urlpinger.core.pinger import is_acceptable_status_code, ping


@pytest.mark.asyncio
async def test_is_acceptable_status_code():
    assert await is_acceptable_status_code(200, [200, 201, 202]) is True
    assert await is_acceptable_status_code(404, [200, 201, 202]) is False


class TestPingFunction(unittest.TestCase):
    @patch("aiohttp.ClientSession")
    async def test_http_ping_success(self, mock_session):
        # Arrange
        config = MagicMock(check_type="http", endpoint="https://example.com")
        mock_response = MagicMock(status=200)
        mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = (
            mock_response
        )

        # Act
        status, error, response_time = await ping(config)

        # Assert
        self.assertEqual(status, 200)
        self.assertIsNone(error)
        self.assertIsNotNone(response_time)

    @patch("aiohttp.ClientSession")
    async def test_http_ping_failure(self, mock_session):
        # Arrange
        config = MagicMock(check_type="http", endpoint="https://example.com")
        mock_session.return_value.__aenter__.return_value.get.side_effect = Exception(
            "Mocked exception"
        )

        # Act
        status, error, response_time = await ping(config)

        # Assert
        self.assertIsNone(status)
        self.assertIsInstance(error, Exception)
        self.assertIsNone(response_time)

    @patch("asyncio.create_subprocess_exec")
    async def test_ping_success(self, mock_create_subprocess_exec):
        # Arrange
        config = MagicMock(check_type="ping", endpoint="example.com")
        mock_process = MagicMock(returncode=0)
        mock_create_subprocess_exec.return_value = mock_process

        # Act
        status, error, response_time = await ping(config)

        # Assert
        self.assertEqual(status, 0)
        self.assertIsNone(error)
        self.assertIsNotNone(response_time)

    @patch("asyncio.create_subprocess_exec")
    async def test_ping_failure(self, mock_create_subprocess_exec):
        # Arrange
        config = MagicMock(check_type="ping", endpoint="example.com")
        mock_process = MagicMock(returncode=1)
        mock_create_subprocess_exec.return_value = mock_process

        # Act
        status, error, response_time = await ping(config)

        # Assert
        self.assertIsNone(status)
        self.assertIsInstance(error, Exception)
        self.assertIsNone(response_time)

    async def test_unknown_check_type(self):
        # Arrange
        config = MagicMock(check_type="unknown", endpoint="example.com")

        # Act
        status, error, response_time = await ping(config)

        # Assert
        self.assertIsNone(status)
        self.assertIsInstance(error, Exception)
        self.assertIsNone(response_time)

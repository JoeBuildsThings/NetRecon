import socket

import pytest

from recon.validator import TargetValidationError, normalize_and_validate

BLOCKED = [
    "127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1", "2002:7f00:1::",
    "localhost", "http://localhost:8080/", "http://169.254.169.254/latest/",
    "[::1]:80", "foo.local", "http://user@127.0.0.1/",
    "127.1", "0x7f.0.0.1", "2130706433", "",
]


@pytest.mark.parametrize("target", BLOCKED)
def test_blocked_targets(target):
    with pytest.raises(TargetValidationError):
        normalize_and_validate(target)


@pytest.mark.parametrize("target", ["1.1.1.1", "8.8.8.8:53", "https://1.1.1.1/path?x=1", "[2606:4700:4700::1111]:443"])
def test_public_ips_allowed(target):
    result = normalize_and_validate(target)
    assert result.is_ip is True


def test_hostname_resolving_public(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    result = normalize_and_validate("example.com")
    assert result.primary_ip == "93.184.216.34"
    assert result.is_ip is False


def test_dns_rebinding_mixed_answers_blocked(monkeypatch):
    answers = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("10.0.0.7", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(TargetValidationError):
        normalize_and_validate("rebind.example.com")


def test_hostname_with_crlf_rejected():
    with pytest.raises(TargetValidationError):
        normalize_and_validate("example.com\r\nX: y")


def test_overlong_input_rejected():
    with pytest.raises(TargetValidationError):
        normalize_and_validate("a" * 300 + ".com")

#!/usr/bin/env python3
"""
Tests fuer Domain-Scanner v2 (Phase 1):
- DNSSEC + CAA + NS-Diversitaet (_check_dns_security)
- ASN/IP-Mapping (_check_asn_mapping)
- Tech-Fingerprint (_check_tech_stack)

Sicherheitsfokus:
- SSRF-Schutz darf durch neue Module NICHT unterlaufen werden.
- Fail-closed bei Resolver-Fehlern.
- Output enthaelt keine internen Klartext-Details.

Lauf mit: pytest backend/tests/test_scanner_v2.py -v
Keine echten DNS/HTTP-Aufrufe — alles wird gemockt.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Pfad-Setup, damit "from routers import public" funktioniert
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from routers import public  # noqa: E402


# ---------------------------------------------------------------------------
# SSRF-Schutz darf nicht regredieren
# ---------------------------------------------------------------------------

class TestSSRFGuard:
    def test_internal_docker_ip_blocked(self):
        assert public._is_ip_blocked("172.18.0.1") is True

    def test_friegun_vpn_blocked(self):
        assert public._is_ip_blocked("10.8.0.1") is True

    def test_aws_metadata_blocked(self):
        assert public._is_ip_blocked("169.254.169.254") is True

    def test_azure_metadata_blocked(self):
        assert public._is_ip_blocked("168.63.129.16") is True

    def test_loopback_blocked(self):
        assert public._is_ip_blocked("127.0.0.1") is True

    def test_public_ip_allowed(self):
        assert public._is_ip_blocked("1.1.1.1") is False

    def test_invalid_ip_fail_closed(self):
        assert public._is_ip_blocked("not-an-ip") is True


# ---------------------------------------------------------------------------
# Domain-Validierung — Regression-Schutz
# ---------------------------------------------------------------------------

class TestDomainValidation:
    def test_normal_domain(self):
        ok, clean, _err = public._validate_domain("kyberguard.de")
        assert ok and clean == "kyberguard.de"

    def test_protocol_smuggling_blocked(self):
        ok, _clean, _err = public._validate_domain("javascript:alert(1)")
        assert ok is False

    def test_file_protocol_blocked(self):
        ok, _clean, _err = public._validate_domain("file:///etc/passwd")
        assert ok is False

    def test_ip_literal_blocked(self):
        ok, _clean, _err = public._validate_domain("127.0.0.1")
        assert ok is False

    def test_localhost_blocked(self):
        ok, _clean, _err = public._validate_domain("localhost")
        assert ok is False

    def test_oversize_blocked(self):
        ok, _clean, _err = public._validate_domain("a" * 300 + ".de")
        assert ok is False


# ---------------------------------------------------------------------------
# NS-Provider-Heuristik
# ---------------------------------------------------------------------------

class TestNSProvider:
    def test_cloudflare_detected(self):
        assert public._ns_provider("ns1.cloudflare.com") == "Cloudflare"

    def test_aws_detected(self):
        assert public._ns_provider("ns-123.awsdns-12.org") == "AWS Route 53"

    def test_unknown_returns_apex(self):
        assert public._ns_provider("ns1.example-dns.com") == "example-dns.com"


# ---------------------------------------------------------------------------
# DNS-Security-Modul (mit Mocked Resolver)
# ---------------------------------------------------------------------------

class _FakeResolver:
    """Minimaler Resolver-Mock fuer dns.resolver-Aufrufe."""

    def __init__(self, responses: dict, raise_on=None):
        # responses: {(qname, rtype): rrset_list}
        self._responses = responses
        self._raise_on = raise_on or {}
        self.lifetime = 5.0
        self.timeout = 3.0

    def use_edns(self, *_a, **_kw):
        pass

    def resolve(self, qname, rtype, raise_on_no_answer=True):
        key = (qname, rtype)
        if key in self._raise_on:
            raise self._raise_on[key]
        rrset = self._responses.get(key)
        # Fake "Answer"-Objekt mit .rrset und .response.flags
        class _Resp:
            flags = 0  # AD-Bit nicht gesetzt
        class _Ans:
            pass
        ans = _Ans()
        ans.rrset = rrset
        ans.response = _Resp()
        if rrset is None and raise_on_no_answer:
            import dns.resolver
            raise dns.resolver.NoAnswer
        return ans


@pytest.mark.asyncio
async def test_dns_security_unsigned_domain():
    """Domain ohne DNSSEC sollte status='unsigned' liefern."""
    fake = _FakeResolver(responses={})

    with patch.object(public.dns.resolver, "Resolver", lambda: fake):
        result = await public._check_dns_security("example.com")

    assert result["dnssec"]["signed"] is False
    assert result["dnssec"]["status"] == "unsigned"
    assert result["caa"]["exists"] is False
    assert result["ns"]["count"] == 0


@pytest.mark.asyncio
async def test_dns_security_ns_diversity():
    """Mehrere NS bei gleichem Provider → single_provider_redundant."""
    class _Stub:
        def __str__(self):
            return self.name

    ns1 = _Stub(); ns1.name = "ns1.cloudflare.com."
    ns2 = _Stub(); ns2.name = "ns2.cloudflare.com."

    fake = _FakeResolver(responses={
        ("kyberguard.de", "NS"): [ns1, ns2],
    })
    with patch.object(public.dns.resolver, "Resolver", lambda: fake):
        result = await public._check_dns_security("kyberguard.de")

    assert result["ns"]["count"] == 2
    assert result["ns"]["providers"] == ["Cloudflare"]
    assert result["ns"]["diversity"] == "single_provider_redundant"


# ---------------------------------------------------------------------------
# ASN-Mapping — DoS-Schutz
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_asn_mapping_caps_ip_count(monkeypatch):
    """Domain mit 1000 A-Records darf nicht 1000 ipinfo-Calls absetzen."""
    # Fake A-Records: 50 IPs
    class _Stub:
        def __init__(self, ip): self.ip = ip
        def __str__(self): return self.ip

    fake_ips = [_Stub(f"1.2.3.{i}") for i in range(50)]
    fake = _FakeResolver(responses={
        ("test.example", "A"): fake_ips,
        ("test.example", "AAAA"): None,
    })
    monkeypatch.setattr(public.dns.resolver, "Resolver", lambda: fake)

    # Httpx-Client mocken — keine echten Calls
    class _FakeClient:
        async def get(self, *a, **kw):
            class _R:
                status_code = 404
                def json(self): return {}
            return _R()

    result = await public._check_asn_mapping("test.example", _FakeClient())
    # Wir kappen bei _MAX_IPS_PER_DOMAIN
    assert result["ip_count"] <= public._MAX_IPS_PER_DOMAIN


# ---------------------------------------------------------------------------
# Tech-Fingerprint — Headers + Body
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tech_stack_detects_wordpress_via_pingback():
    class _Resp:
        def __init__(self):
            self.headers = {"X-Pingback": "https://example.com/xmlrpc.php", "Server": "nginx/1.18"}
            self.text = "<html><head></head><body>hello</body></html>"

    class _FakeClient:
        async def get(self, *a, **kw):
            return _Resp()

    result = await public._check_tech_stack("example.com", _FakeClient())
    assert result["checked"] is True
    assert "WordPress" in result["technologies"]
    assert "nginx" in result["technologies"]


@pytest.mark.asyncio
async def test_tech_stack_body_size_limited():
    """Body > 64 KB darf nicht den ganzen Speicher fluten."""
    huge_body = "x" * (200 * 1024) + "wp-content/"

    class _Resp:
        def __init__(self):
            self.headers = {}
            self.text = huge_body

    class _FakeClient:
        async def get(self, *a, **kw):
            return _Resp()

    result = await public._check_tech_stack("example.com", _FakeClient())
    # Marker liegt nach 200KB → wegen 64KB-Cap nicht erkannt: erwartet
    assert "WordPress" not in result["technologies"]
    assert result["checked"] is True

from __future__ import annotations

from bugfinder.utils.crypto import detect_high_entropy_strings, md5, sha256, shannon_entropy


class TestCrypto:
    def test_sha256(self) -> None:
        assert sha256("hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_md5(self) -> None:
        assert md5("hello") == "5d41402abc4b2a76b9719d911017c592"

    def test_shannon_entropy_uniform(self) -> None:
        e = shannon_entropy(b"\x00\x01\x02\x03")
        assert e > 0

    def test_shannon_entropy_empty(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_shannon_entropy_same_byte(self) -> None:
        assert shannon_entropy(b"\x00\x00\x00") == 0.0

    def test_detect_high_entropy_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j6Z1"
        results = detect_high_entropy_strings(jwt)
        assert len(results) > 0
        assert any(r["pattern"] == "jwt" for r in results)

    def test_detect_github_token(self) -> None:
        text = "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd"
        results = detect_high_entropy_strings(text)
        assert len(results) > 0
        assert any(r["pattern"] == "github_token" for r in results)

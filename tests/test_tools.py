"""Micro-tool tests.

Where a standard defines test vectors (RFC 4226 HOTP, RFC 6238 TOTP, RFC 4648
base encodings, RFC 2202/4231 HMAC) the vectors are used directly, so a broken
or substituted implementation fails loudly instead of being merely
self-consistent.
"""

from __future__ import annotations

import base64
import math
import unittest

from lockbox.tools import TOOLS, by_category, get, run, search as tool_search
from lockbox.tools.analysis import analyze, analyze_characters, charset_size, entropy_bits
from lockbox.tools.commonlist import is_common
from lockbox.tools.encoding import (
    base64_decode, base64_encode, compare_digests, hash_text, hex_decode, hex_encode,
    hmac_text, json_format, json_validate, parse_url, regex_test, transform, url_decode,
    url_encode,
)
from lockbox.tools.generators import (
    build_alphabet, generate_api_key, generate_passphrase, generate_password,
    generate_pronounceable, generate_recovery_codes, generate_username, generate_uuid,
    random_string, secure_random_number,
)
from lockbox.tools.misc import entropy_calculator, password_age, security_checklist
from lockbox.tools.otp import (
    OTPConfig, build_otpauth, generate_secret, hotp, parse_otpauth, time_remaining, totp, verify,
)
from lockbox.tools.qr import encode as qr_encode, to_pbm, to_svg, to_text
from lockbox.tools.wordlist import WORDS, bits_per_word

RFC4226_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC6238_SHA256 = base64.b32encode(b"12345678901234567890123456789012").decode()
RFC6238_SHA512 = base64.b32encode(
    b"1234567890123456789012345678901234567890123456789012345678901234"
).decode()


class TestPasswordGenerator(unittest.TestCase):
    def test_length_and_uniqueness(self):
        values = {generate_password(length=24).value for _ in range(200)}
        self.assertEqual(len(values), 200)
        self.assertTrue(all(len(v) == 24 for v in values))

    def test_includes_every_requested_class(self):
        for _ in range(50):
            value = generate_password(length=12).value
            self.assertTrue(any(c.islower() for c in value))
            self.assertTrue(any(c.isupper() for c in value))
            self.assertTrue(any(c.isdigit() for c in value))
            self.assertTrue(any(not c.isalnum() for c in value))

    def test_class_switches_are_respected(self):
        value = generate_password(length=32, uppercase=False, symbols=False).value
        self.assertTrue(value.islower() or value.isalnum())
        self.assertFalse(any(c.isupper() for c in value))

    def test_exclusions(self):
        value = generate_password(length=64, exclude="abc0123").value
        self.assertFalse(set(value) & set("abc0123"))

    def test_ambiguous_exclusion(self):
        value = generate_password(length=200, exclude_ambiguous=True).value
        self.assertFalse(set(value) & set("Il1O0o"))

    def test_custom_alphabet(self):
        value = generate_password(length=40, custom_alphabet="ACGT").value
        self.assertTrue(set(value) <= set("ACGT"))

    def test_entropy_matches_the_alphabet(self):
        result = generate_password(length=16, symbols=False)
        self.assertAlmostEqual(
            result.entropy_bits, 16 * math.log2(result.alphabet_size), places=6
        )

    def test_impossible_parameters_raise(self):
        with self.assertRaises(ValueError):
            generate_password(length=2)
        with self.assertRaises(ValueError):
            generate_password(length=20, custom_alphabet="a")
        with self.assertRaises(ValueError):
            build_alphabet(exclude="".join(chr(i) for i in range(32, 127)))

    def test_distribution_is_roughly_uniform(self):
        counts = {}
        for _ in range(400):
            for char in generate_password(length=40, custom_alphabet="abcd",
                                          require_each_class=False).value:
                counts[char] = counts.get(char, 0) + 1
        total = sum(counts.values())
        for char in "abcd":
            share = counts.get(char, 0) / total
            self.assertTrue(0.20 < share < 0.30, f"{char}: {share:.3f}")


class TestOtherGenerators(unittest.TestCase):
    def test_passphrase(self):
        result = generate_passphrase(words=5, separator="-")
        self.assertEqual(len(result.value.split("-")), 5)
        self.assertAlmostEqual(result.entropy_bits, 5 * bits_per_word(), places=4)

    def test_passphrase_entropy_tracks_the_actual_list(self):
        small = ["alpha", "bravo", "charlie", "delta"]
        result = generate_passphrase(words=4, wordlist=small)
        self.assertAlmostEqual(result.entropy_bits, 4 * 2, places=6)

    def test_passphrase_extras(self):
        result = generate_passphrase(words=3, capitalize=True, add_number=True, add_symbol=True)
        self.assertTrue(result.value[0].isupper())
        self.assertGreater(result.entropy_bits, 3 * bits_per_word())

    def test_wordlist_is_sane(self):
        self.assertGreater(len(WORDS), 1000)
        self.assertEqual(len(WORDS), len(set(WORDS)))
        self.assertTrue(all(w.isalpha() and w.islower() for w in WORDS))

    def test_pronounceable_alternates(self):
        value = generate_pronounceable(length=12, capitalize=False, add_digits=0).value
        self.assertTrue(all(c in "aeiou" for c in value[1::2]))

    def test_username(self):
        for style in ("word", "pronounceable", "random"):
            self.assertTrue(generate_username(style=style).value)
        with self.assertRaises(ValueError):
            generate_username(style="nope")

    def test_api_key_encodings(self):
        self.assertTrue(generate_api_key(prefix="lk_", nbytes=32).value.startswith("lk_"))
        self.assertEqual(len(generate_api_key(nbytes=16, encoding="hex").value), 32)
        self.assertEqual(generate_api_key(nbytes=32).entropy_bits, 256)
        with self.assertRaises(ValueError):
            generate_api_key(encoding="rot13")

    def test_recovery_codes(self):
        result = generate_recovery_codes(count=8, groups=3, group_len=4)
        self.assertEqual(len(result["codes"]), 8)
        self.assertEqual(len(set(result["codes"])), 8)
        for code in result["codes"]:
            self.assertEqual([len(part) for part in code.split("-")], [4, 4, 4])
            self.assertFalse(set(code) & set("IO01"))

    def test_uuid(self):
        self.assertEqual(generate_uuid(4).value[14], "4")
        self.assertEqual(generate_uuid(7).value[14], "7")
        with self.assertRaises(ValueError):
            generate_uuid(1)

    def test_secure_random_number_range(self):
        values = secure_random_number(1, 6, 500)
        self.assertEqual(len(values), 500)
        self.assertTrue(all(1 <= v <= 6 for v in values))
        self.assertEqual(len(set(values)), 6)
        with self.assertRaises(ValueError):
            secure_random_number(10, 1)

    def test_random_string_validation(self):
        self.assertEqual(len(random_string(10, "ab")), 10)
        with self.assertRaises(ValueError):
            random_string(0, "ab")


class TestAnalysis(unittest.TestCase):
    def test_charset_size(self):
        self.assertEqual(charset_size("abc"), 26)
        self.assertEqual(charset_size("abcABC"), 52)
        self.assertEqual(charset_size("abcABC123"), 62)

    def test_entropy_formula(self):
        self.assertAlmostEqual(entropy_bits(62, 10), 10 * math.log2(62), places=6)
        self.assertEqual(entropy_bits(1, 10), 0)

    def test_common_password_is_destroyed(self):
        self.assertLess(analyze("password").estimated_bits, 20)
        self.assertLess(analyze("password123!").estimated_bits, 30)

    def test_generated_password_scores_well(self):
        result = analyze(generate_password(length=24).value)
        self.assertGreater(result.estimated_bits, 80)
        self.assertEqual(result.strength, "very strong")

    def test_pattern_detection(self):
        self.assertTrue(analyze("aaabbbccc").patterns)
        self.assertTrue(any("sequence" in p for p in analyze("abcdefgh1").patterns))
        self.assertTrue(any("keyboard" in p for p in analyze("qwertyui").patterns))
        self.assertTrue(any("year" in p for p in analyze("Summer2024!").patterns))
        self.assertTrue(any("repeated block" in p for p in analyze("abcabcabc").patterns))
        self.assertTrue(any("dictionary" in p for p in analyze("correcthorse").patterns))

    def test_leetspeak_is_seen_through(self):
        self.assertTrue(any("dictionary" in p for p in analyze("p4ssw0rd").patterns))

    def test_empty(self):
        result = analyze("")
        self.assertEqual(result.length, 0)
        self.assertEqual(result.estimated_bits, 0)

    def test_common_list_matching(self):
        self.assertTrue(is_common("password"))
        self.assertTrue(is_common("Password1"))
        self.assertTrue(is_common("letmein!"))
        self.assertFalse(is_common(generate_password(length=20).value))

    def test_crack_times_present(self):
        self.assertEqual(len(analyze("abc").crack_times), 4)

    def test_character_analyzer_flags_hidden_characters(self):
        result = analyze_characters("hello\u200bworld")
        self.assertIn("U+200B", result["invisible_or_control"])
        self.assertEqual(result["categories"]["lowercase"], 10)


class TestOTP(unittest.TestCase):
    def test_rfc4226_hotp_vectors(self):
        expected = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
        for counter, code in enumerate(expected):
            self.assertEqual(hotp(RFC4226_SECRET, counter), code)

    def test_rfc6238_totp_sha1_vectors(self):
        for at, code in ((59, "94287082"), (1111111109, "07081804"),
                         (1111111111, "14050471"), (1234567890, "89005924"),
                         (2000000000, "69279037"), (20000000000, "65353130")):
            self.assertEqual(totp(RFC4226_SECRET, at=at, digits=8), code)

    def test_rfc6238_totp_sha256_vectors(self):
        for at, code in ((59, "46119246"), (1111111109, "68084774"),
                         (20000000000, "77737706")):
            self.assertEqual(
                totp(RFC6238_SHA256, at=at, digits=8, algorithm="SHA256"), code
            )

    def test_rfc6238_totp_sha512_vectors(self):
        for at, code in ((59, "90693936"), (1111111109, "25091201"),
                         (20000000000, "47863826")):
            self.assertEqual(
                totp(RFC6238_SHA512, at=at, digits=8, algorithm="SHA512"), code
            )

    def test_code_changes_with_the_period(self):
        first = totp(RFC4226_SECRET, at=1020)   # step 34 starts at t=1020
        self.assertEqual(first, totp(RFC4226_SECRET, at=1049))
        self.assertNotEqual(first, totp(RFC4226_SECRET, at=1050))

    def test_time_remaining(self):
        self.assertAlmostEqual(time_remaining(30, at=1000), 20.0, places=6)

    def test_verify_window(self):
        self.assertTrue(verify(RFC4226_SECRET, totp(RFC4226_SECRET, at=1000), at=1000))
        self.assertTrue(verify(RFC4226_SECRET, totp(RFC4226_SECRET, at=970), at=1000))
        self.assertFalse(verify(RFC4226_SECRET, "000000", at=1000, window=0))

    def test_generated_secret_is_usable_and_random(self):
        secrets = {generate_secret() for _ in range(50)}
        self.assertEqual(len(secrets), 50)
        self.assertTrue(totp(secrets.pop()).isdigit())

    def test_bad_secret_raises(self):
        for bad in ("", "!!!!", "1"):
            with self.assertRaises(ValueError):
                totp(bad)

    def test_otpauth_round_trip(self):
        config = OTPConfig(secret=generate_secret(), label="me@example.com",
                           issuer="Example Inc", digits=8, period=60, algorithm="SHA256")
        parsed = parse_otpauth(build_otpauth(config))
        self.assertEqual(parsed.secret, config.secret)
        self.assertEqual(parsed.issuer, config.issuer)
        self.assertEqual(parsed.label, config.label)
        self.assertEqual(parsed.digits, 8)
        self.assertEqual(parsed.period, 60)
        self.assertEqual(parsed.algorithm, "SHA256")

    def test_parse_bare_secret(self):
        self.assertEqual(parse_otpauth("jbswy3dpehpk3pxp").secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(parse_otpauth("JBSW Y3DP EHPK 3PXP").secret, "JBSWY3DPEHPK3PXP")

    def test_bare_secret_of_junk_is_rejected(self):
        # Every character here is outside the base32 alphabet, so normalising
        # leaves nothing. This must raise rather than yield an empty secret the
        # caller then stores as a working TOTP configuration.
        for junk in ("!!! not base32 !!!", "", "----", "0189"):
            with self.subTest(junk=junk), self.assertRaises(ValueError):
                parse_otpauth(junk)

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            OTPConfig(secret=generate_secret(), algorithm="MD5").validate()
        with self.assertRaises(ValueError):
            OTPConfig(secret=generate_secret(), digits=99).validate()


class TestQR(unittest.TestCase):
    def test_dimensions_and_finders(self):
        matrix = qr_encode("hello")
        self.assertEqual(len(matrix), 21)  # version 1
        for row in range(7):
            self.assertEqual(matrix[row][0], 1 if row in (0, 6) else matrix[row][0])
        self.assertEqual(matrix[0][:7], [1, 1, 1, 1, 1, 1, 1])
        self.assertEqual([matrix[r][0] for r in range(7)], [1, 1, 1, 1, 1, 1, 1])

    def test_timing_pattern(self):
        matrix = qr_encode("hello")
        size = len(matrix)
        for i in range(8, size - 8):
            self.assertEqual(matrix[6][i], 1 if i % 2 == 0 else 0)
            self.assertEqual(matrix[i][6], 1 if i % 2 == 0 else 0)

    def test_version_grows_with_payload(self):
        self.assertLess(len(qr_encode("short")), len(qr_encode("x" * 150)))

    def test_otpauth_uri_fits(self):
        uri = build_otpauth(OTPConfig(secret=generate_secret(), label="user@example.com",
                                      issuer="Example"))
        self.assertTrue(qr_encode(uri, ec="M"))

    def test_too_much_data_raises(self):
        with self.assertRaises(ValueError):
            qr_encode("x" * 5000)

    def test_renderers(self):
        matrix = qr_encode("hi")
        self.assertIn("\u2588", to_text(matrix))
        svg = to_svg(matrix)
        self.assertTrue(svg.startswith("<svg"))
        self.assertNotIn("http://", svg.replace('xmlns="http://www.w3.org/2000/svg"', ""))
        self.assertTrue(to_pbm(matrix).startswith(b"P1\n"))

    def test_svg_has_no_external_references(self):
        svg = to_svg(qr_encode("hi"))
        for marker in ("<image", "xlink:href", "@import", "<script"):
            self.assertNotIn(marker, svg)

    def test_matches_reference_encoder_if_available(self):
        try:
            import qrcode  # type: ignore
            from qrcode.util import MODE_8BIT_BYTE, QRData  # type: ignore
        except ImportError:
            self.skipTest("reference qrcode package not installed")
        for data in ("hello world", "x" * 100, "otpauth://totp/a?secret=JBSWY3DP"):
            for name, level in (("L", qrcode.constants.ERROR_CORRECT_L),
                                ("M", qrcode.constants.ERROR_CORRECT_M)):
                reference = qrcode.QRCode(error_correction=level, border=0)
                reference.add_data(QRData(data.encode(), mode=MODE_8BIT_BYTE))
                reference.make(fit=True)
                expected = [[1 if v else 0 for v in row] for row in reference.modules]
                self.assertEqual(len(qr_encode(data, ec=name)), len(expected))


class TestEncoding(unittest.TestCase):
    def test_base64_rfc4648_vectors(self):
        for text, encoded in (("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"),
                              ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="),
                              ("foobar", "Zm9vYmFy")):
            self.assertEqual(base64_encode(text), encoded)
            self.assertEqual(base64_decode(encoded), text)

    def test_base64_tolerates_missing_padding_and_whitespace(self):
        self.assertEqual(base64_decode("Zm9v\nYmFy"), "foobar")
        self.assertEqual(base64_decode("Zm9vYg"), "foob")

    def test_base64_rejects_garbage(self):
        with self.assertRaises(ValueError):
            base64_decode("!!!!not base64!!!!")

    def test_hex_round_trip(self):
        self.assertEqual(hex_encode("hi"), "6869")
        self.assertEqual(hex_decode("6869"), "hi")
        with self.assertRaises(ValueError):
            hex_decode("zz")

    def test_url_coding(self):
        self.assertEqual(url_encode("a b&c=d"), "a%20b%26c%3Dd")
        self.assertEqual(url_decode("a%20b"), "a b")

    def test_hash_vectors(self):
        self.assertEqual(
            hash_text("abc", "sha256")["value"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(hash_text("", "sha1")["value"],
                         "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertTrue(hash_text("x", "md5")["warning"])
        self.assertFalse(hash_text("x", "sha256")["warning"])
        with self.assertRaises(ValueError):
            hash_text("x", "rot13")

    def test_hmac_rfc4231_case_1(self):
        result = hmac_text("\x0b" * 20, "Hi There", "sha256")
        self.assertEqual(
            result["value"],
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )

    def test_constant_time_compare(self):
        self.assertTrue(compare_digests("ABC123", "abc123"))
        self.assertFalse(compare_digests("abc", "abd"))

    def test_json_tools(self):
        self.assertIn("\n", json_format('{"a":1}'))
        self.assertTrue(json_validate('{"a":1}')["valid"])
        invalid = json_validate("{oops}")
        self.assertFalse(invalid["valid"])
        self.assertIn("line", invalid)

    def test_regex_tester(self):
        result = regex_test(r"(\d+)", "a1 b22 c333")
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["matches"][2]["groups"], ["333"])
        self.assertFalse(regex_test("([", "x")["valid"])

    def test_url_inspector(self):
        result = parse_url("https://user:pw@xn--80ak6aa92e.com:8443/a?b=1#f")
        self.assertTrue(result["has_userinfo"])
        self.assertTrue(result["punycode_host"])
        self.assertTrue(result["is_https"])
        self.assertEqual(result["port"], 8443)
        self.assertEqual(result["query"], {"b": "1"})

    def test_transforms(self):
        self.assertEqual(transform("Hello World", "snake_case"), "hello_world")
        self.assertEqual(transform("Hello World", "kebab_case"), "hello-world")
        self.assertEqual(transform("hello world", "camel_case"), "helloWorld")
        self.assertEqual(transform("b\na\nb", "unique_lines"), "b\na")
        self.assertEqual(transform("a\u200bb", "strip_invisible"), "ab")
        with self.assertRaises(ValueError):
            transform("x", "explode")


class TestMisc(unittest.TestCase):
    def test_password_age(self):
        result = password_age(0, warn_days=1, now=86400 * 400)
        self.assertTrue(result["stale"])
        self.assertAlmostEqual(result["days"], 400, places=1)
        self.assertFalse(password_age(86400 * 399, warn_days=365, now=86400 * 400)["stale"])

    def test_entropy_calculator(self):
        self.assertAlmostEqual(
            entropy_calculator(alphabet_size=95, length=16)["bits"],
            round(16 * math.log2(95), 2),
        )
        self.assertAlmostEqual(
            entropy_calculator(words=6, wordlist_size=7776)["bits"],
            round(6 * math.log2(7776), 2),
        )
        with self.assertRaises(ValueError):
            entropy_calculator()

    def test_checklist(self):
        items = security_checklist({"permissions": "0o600", "auto_lock_seconds": 300,
                                    "audit_findings": 0, "has_recent_backup": True})
        auto = [i for i in items if i["auto"]]
        self.assertTrue(auto)
        self.assertTrue(all(i["ok"] for i in auto))
        self.assertTrue(any(i["ok"] is None for i in items))


class TestRegistry(unittest.TestCase):
    def test_every_tool_loads_and_is_local(self):
        for tool_id, tool in TOOLS.items():
            self.assertFalse(tool.network, tool_id)
            self.assertTrue(callable(tool.load()), tool_id)
            self.assertTrue(tool.summary.strip(), tool_id)

    def test_spec_required_tools_are_present(self):
        required = {
            "password", "passphrase", "strength", "entropy", "random_string", "username",
            "totp", "totp_secret", "qr_svg", "recovery_codes", "api_key", "uuid", "hash",
            "hmac", "base64_encode", "base64_decode", "url_encode", "url_decode",
            "json_format", "json_validate", "regex", "characters", "random_number",
            "password_age", "password_batch", "token", "transform", "checklist",
        }
        self.assertTrue(required <= set(TOOLS), required - set(TOOLS))

    def test_categories_are_populated(self):
        self.assertTrue(all(by_category().values()))

    def test_search(self):
        self.assertTrue(tool_search("passphrase"))
        self.assertEqual(len(tool_search("")), len(TOOLS))

    def test_run_and_unknown(self):
        self.assertEqual(len(run("password", length=16).value), 16)
        with self.assertRaises(KeyError):
            get("no-such-tool")


if __name__ == "__main__":
    unittest.main()

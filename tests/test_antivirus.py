"""Antivirus engine tests: verdicts, archives, cancellation, quarantine."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from modules.antivirus import (
    ASEAntivirus,
    ScanCancellationToken,
    VERDICTS,
    _EICAR,
)
from core.exceptions import ASEQuarantineError, ASEScanError


class AntivirusTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.av = ASEAntivirus(self.root / "av")
        self.av.start()

    def tearDown(self):
        self.av.stop()
        self.temp.cleanup()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path


class VerdictTests(AntivirusTestCase):
    def test_clean_file_is_not_declared_safe(self):
        result = self.av.scan_file(self.write("clean.txt", "ordinary document"))
        self.assertEqual(result["status"], "no_known_indicators")
        self.assertEqual(result["findings"], [])
        joined = " ".join(result["explanations"]).lower()
        self.assertIn("does not prove", joined)

    def test_eicar_detected_as_malicious(self):
        result = self.av.scan_file(self.write("test.com", _EICAR))
        self.assertEqual(result["status"], "malicious_indicator")
        self.assertEqual(result["findings"][0]["rule"], "EICAR_TEST_FILE")
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertTrue(result["explanations"])

    def test_double_extension_is_suspicious(self):
        result = self.av.scan_file(self.write("invoice.pdf.exe", "harmless text"))
        self.assertEqual(result["status"], "suspicious")
        self.assertIn("DOUBLE_EXTENSION", [item["rule"] for item in result["findings"]])

    def test_local_signature_match(self):
        path = self.write("sample.bin", "some bytes")
        digest = self.av.hash_file(path)
        self.av.add_signature(digest)
        result = self.av.scan_file(path)
        self.assertEqual(result["status"], "malicious_indicator")
        self.assertIn("LOCAL_SHA256_SIGNATURE", [item["rule"] for item in result["findings"]])

    def test_scan_does_not_modify_file(self):
        path = self.write("test.com", _EICAR)
        before = path.read_bytes()
        self.av.scan_file(path)
        self.assertEqual(path.read_bytes(), before)

    def test_symlink_refused(self):
        target = self.write("target.txt", "text")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(self.av.scan_file(link)["status"], "scan_error")

    def test_missing_file_reports_scan_error(self):
        self.assertEqual(self.av.scan_file(self.root / "nope.txt")["status"], "scan_error")

    def test_oversized_file_is_scan_incomplete(self):
        self.av.max_file_size = 10
        result = self.av.scan_file(self.write("big.txt", "x" * 100))
        self.assertEqual(result["status"], "scan_incomplete")
        self.assertEqual(result["reason"], "file_size_limit")

    def test_documented_verdict_set(self):
        self.assertEqual(set(VERDICTS), {
            "no_known_indicators", "suspicious", "malicious_indicator",
            "scan_incomplete", "scan_error",
        })

    def test_signature_validation_rejects_bad_digest(self):
        with self.assertRaises(ASEScanError):
            self.av.add_signature("not-a-sha256")


class ArchiveTests(AntivirusTestCase):
    def _zip(self, name, members):
        path = self.root / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for member_name, payload in members.items():
                archive.writestr(member_name, payload)
        return path

    def test_eicar_inside_archive_detected(self):
        path = self._zip("sample.zip", {"inner.txt": _EICAR})
        result = self.av.scan_file(path)
        self.assertIn("EICAR_TEST_FILE", [item["rule"] for item in result["findings"]])
        self.assertEqual(result["status"], "malicious_indicator")

    def test_clean_archive_is_not_flagged(self):
        path = self._zip("clean.zip", {"a.txt": "hello", "b.txt": "world"})
        self.assertEqual(self.av.scan_file(path)["status"], "no_known_indicators")

    def test_member_count_limit_enforced(self):
        self.av.max_archive_members = 2
        path = self._zip("many.zip", {"f%d.txt" % i: "x" for i in range(10)})
        rules = [item["rule"] for item in self.av.scan_file(path)["findings"]]
        self.assertIn("ARCHIVE_MEMBER_LIMIT", rules)

    def test_member_size_limit_enforced(self):
        self.av.max_archive_member_size = 8
        path = self._zip("large.zip", {"big.txt": "y" * 500})
        rules = [item["rule"] for item in self.av.scan_file(path)["findings"]]
        self.assertIn("ARCHIVE_MEMBER_SIZE_LIMIT", rules)

    def test_corrupt_archive_does_not_crash(self):
        path = self.write("broken.zip", b"PK\x03\x04" + b"\x00" * 40)
        self.assertIn(self.av.scan_file(path)["status"], VERDICTS)


class ScanProfileTests(AntivirusTestCase):
    def test_scan_path_reports_verdict_counts(self):
        self.write("dir/clean.txt", "fine")
        self.write("dir/bad.com", _EICAR)
        report = self.av.scan_path(self.root / "dir")
        self.assertEqual(report["total"], 2)
        self.assertEqual(report["detections"], 1)
        self.assertEqual(report["verdict_counts"]["malicious_indicator"], 1)
        self.assertEqual(report["verdict_counts"]["no_known_indicators"], 1)
        self.assertEqual(report["status"], "completed")

    def test_detection_details_include_reasons(self):
        self.write("bad.com", _EICAR)
        report = self.av.scan_path(self.root)
        self.assertTrue(report["detection_details"])
        self.assertTrue(report["detection_details"][0]["reasons"])

    def test_cancellation_stops_scan(self):
        for index in range(20):
            self.write("many/f%d.txt" % index, "content %d" % index)
        token = ScanCancellationToken()
        token.cancel()
        report = self.av.scan_path(self.root / "many", token=token)
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(report["total"], 0)

    def test_quick_scan_runs(self):
        report = self.av.quick_scan()
        self.assertIn(report["status"], ("completed", "cancelled"))
        self.assertIn("targets", report)

    def test_full_scan_with_explicit_root(self):
        self.write("full/a.txt", "data")
        report = self.av.full_scan(roots=[str(self.root / "full")])
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["scan_type"], "full")

    def test_scan_missing_target_raises(self):
        with self.assertRaises(ASEScanError):
            self.av.scan_path(self.root / "does-not-exist")


class QuarantineTests(AntivirusTestCase):
    def test_quarantine_requires_authorization(self):
        path = self.write("bad.com", _EICAR)
        with self.assertRaises(ASEQuarantineError):
            self.av.quarantine_file(path)
        self.assertTrue(path.exists())

    def test_quarantine_refuses_clean_file(self):
        path = self.write("clean.txt", "harmless")
        with self.assertRaises(ASEQuarantineError):
            self.av.quarantine_file(path, authorized=True)
        self.assertTrue(path.exists())

    def test_quarantine_moves_and_records_metadata(self):
        path = self.write("bad.com", _EICAR)
        digest = self.av.hash_file(path)
        result = self.av.quarantine_file(path, authorized=True)
        self.assertEqual(result["status"], "quarantined")
        self.assertFalse(path.exists())
        self.assertEqual(result["sha256"], digest)
        items = self.av.list_quarantine()
        self.assertEqual(len(items), 1)
        stored = self.av.quarantine_dir / items[0]["stored_name"]
        self.assertTrue(stored.exists())
        self.assertEqual(stored.stat().st_mode & 0o777, 0o600)

    def test_restore_round_trip_verifies_integrity(self):
        path = self.write("bad.com", _EICAR)
        original = path.read_bytes()
        qid = self.av.quarantine_file(path, authorized=True)["quarantine_id"]
        result = self.av.restore_file(qid)
        self.assertEqual(result["status"], "restored")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.av.list_quarantine(), [])

    def test_restore_refuses_when_destination_exists(self):
        path = self.write("bad.com", _EICAR)
        qid = self.av.quarantine_file(path, authorized=True)["quarantine_id"]
        path.write_text("a new file took the name")
        with self.assertRaises(ASEQuarantineError):
            self.av.restore_file(qid)
        self.assertTrue(path.exists())

    def test_restore_detects_tampered_quarantine_content(self):
        path = self.write("bad.com", _EICAR)
        qid = self.av.quarantine_file(path, authorized=True)["quarantine_id"]
        (self.av.quarantine_dir / qid).write_bytes(b"tampered")
        with self.assertRaises(ASEQuarantineError) as ctx:
            self.av.restore_file(qid)
        self.assertIn("integrity", str(ctx.exception).lower())

    def test_unknown_quarantine_id(self):
        with self.assertRaises(ASEQuarantineError):
            self.av.restore_file("does-not-exist")

    def test_quarantine_metadata_persists_across_restart(self):
        path = self.write("bad.com", _EICAR)
        self.av.quarantine_file(path, authorized=True)
        self.av.stop()
        reloaded = ASEAntivirus(self.root / "av")
        reloaded.start()
        try:
            self.assertEqual(len(reloaded.list_quarantine()), 1)
        finally:
            reloaded.stop()

    def test_quarantine_ids_are_unique(self):
        first = self.write("a.com", _EICAR)
        second = self.write("b.com", _EICAR)
        id_one = self.av.quarantine_file(first, authorized=True)["quarantine_id"]
        id_two = self.av.quarantine_file(second, authorized=True)["quarantine_id"]
        self.assertNotEqual(id_one, id_two)
        self.assertEqual(len(self.av.list_quarantine()), 2)


class LimitTests(unittest.TestCase):
    def test_runtime_file_size_cap_cannot_be_raised(self):
        with tempfile.TemporaryDirectory() as folder:
            av = ASEAntivirus(Path(folder) / "av", settings={"max_file_size_mb": 4096})
            self.assertEqual(av.max_file_size, 64 * 1024 * 1024)

    def test_archive_limits_cannot_exceed_hard_caps(self):
        with tempfile.TemporaryDirectory() as folder:
            av = ASEAntivirus(Path(folder) / "av", settings={
                "max_archive_members": 999999,
                "max_archive_member_size_mb": 99999,
                "max_archive_total_size_mb": 99999,
            })
            self.assertEqual(av.max_archive_members, 2000)
            self.assertEqual(av.max_archive_member_size, 32 * 1024 * 1024)
            self.assertEqual(av.max_archive_total_size, 128 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

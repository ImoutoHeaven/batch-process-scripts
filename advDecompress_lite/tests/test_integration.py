"""Real-extractor checks through the lite command-line interface."""

import gzip
import importlib.util
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "advDecompress_lite.py"
SEVEN_ZIP = shutil.which("7z")
RAR = shutil.which("rar")
RAR_SFX = Path(RAR).parent / "default.sfx" if RAR else None


def _write_mixed_zip(path):
    legacy_dir = "フォルダ/".encode("cp932")
    legacy_child = legacy_dir + "日本.txt".encode("cp932")
    dir_placeholder = b"D" * (len(legacy_dir) - 1) + b"/"
    child_placeholder = b"C" * len(legacy_child)
    with zipfile.ZipFile(str(path), "w") as stream:
        directory = zipfile.ZipInfo(dir_placeholder.decode("ascii"))
        directory.external_attr = (0o40775 << 16) | 0x10
        stream.writestr(directory, b"")
        child = zipfile.ZipInfo(child_placeholder.decode("ascii"))
        stream.writestr(child, b"legacy content")
        stream.writestr("新名.txt", b"modern content")
    data = path.read_bytes()
    for placeholder, replacement in (
        (dir_placeholder, legacy_dir),
        (child_placeholder, legacy_child),
    ):
        if data.count(placeholder) != 2:
            raise AssertionError("ZIP fixture name replacement must hit local and central headers")
        data = data.replace(placeholder, replacement)
    path.write_bytes(data)


def _write_alias_mixed_zip(path):
    legacy_raw = b"\xc3\xa9.txt"
    placeholder = b"L" * len(legacy_raw)
    with zipfile.ZipFile(str(path), "w") as stream:
        info = zipfile.ZipInfo(placeholder.decode("ascii"))
        stream.writestr(info, b"legacy content")
        stream.writestr("é.txt", b"modern content")
    data = path.read_bytes()
    if data.count(placeholder) != 2:
        raise AssertionError("ZIP fixture name replacement must hit local and central headers")
    path.write_bytes(data.replace(placeholder, legacy_raw))


@unittest.skipUnless(SEVEN_ZIP, "7z is required for real extraction checks")
class CommandLineIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_cli(self, source, output, *options):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(source), "-o", str(output),
             "--no-lock", *map(str, options)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
            env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=60,
        )

    def make_7z(self, archive, source, *options):
        result = subprocess.run(
            [SEVEN_ZIP, "a", str(archive), str(source), "-y", *options],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def make_rar(self, archive, source, *options):
        result = subprocess.run(
            [RAR, "a", "-y", "-ep1", *options, str(archive), str(source)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def pe_archive(self, archive):
        # Generated PE envelope; the archive is extracted, never executed.
        prefix = bytearray(1024)
        prefix[:2] = b"MZ"
        struct.pack_into("<I", prefix, 60, 128)
        prefix[128:132] = b"PE\0\0"
        struct.pack_into("<H", prefix, 134, 1)
        struct.pack_into("<I", prefix, 168, 512)
        struct.pack_into("<I", prefix, 172, 512)
        return prefix + archive.read_bytes()

    def test_regular_formats_and_directory_shells(self):
        formats = ("zip", "7z", "tar", "tar.gz", "tar.bz2", "tar.xz")
        payload = b"complete extraction\n"
        for extension in formats:
            with self.subTest(extension=extension):
                case = self.root / extension
                case.mkdir()
                archive = case / ("sample." + extension)
                output = case / "out"
                name = "shell/inner/payload.txt"
                if extension == "zip":
                    with zipfile.ZipFile(str(archive), "w") as stream:
                        stream.writestr(name, payload)
                        stream.writestr("shell/inner/资料.txt", b"unicode")
                elif extension == "7z":
                    source = case / "shell" / "inner"
                    source.mkdir(parents=True)
                    (source / "payload.txt").write_bytes(payload)
                    self.make_7z(archive, source.parent)
                else:
                    mode = {"tar": "w", "tar.gz": "w:gz",
                            "tar.bz2": "w:bz2", "tar.xz": "w:xz"}[extension]
                    with tarfile.open(str(archive), mode) as stream:
                        info = tarfile.TarInfo(name)
                        info.size = len(payload)
                        stream.addfile(info, io.BytesIO(payload))
                result = self.run_cli(archive, output, "-dp", "file-content-with-folder")
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual((output / "inner" / "payload.txt").read_bytes(), payload)
                self.assertTrue(archive.exists())
                self.assertFalse(list(output.rglob("*.tar")))

    def test_mixed_zip_manual_codepage_preserves_names_and_asis_keeps_source(self):
        archive = self.root / "mixed.zip"
        _write_mixed_zip(archive)
        output = self.root / "manual-output"
        result = self.run_cli(archive, output, "-dp", "direct", "-tzp", "decode-932")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((output / "フォルダ" / "日本.txt").read_bytes(), b"legacy content")
        self.assertEqual((output / "新名.txt").read_bytes(), b"modern content")
        self.assertTrue(archive.exists())

        asis_output = self.root / "asis-output"
        result = self.run_cli(
            archive,
            asis_output,
            "-dp",
            "direct",
            "-tzp",
            "asis",
            "-sp",
            "delete",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("traditional_zip_asis", result.stdout)
        self.assertTrue(archive.exists())
        self.assertFalse(asis_output.exists())

    @unittest.skipUnless(os.name != "nt", "native rn compatibility is POSIX-specific")
    def test_mixed_zip_alias_mismatch_fails_before_source_delete(self):
        archive = self.root / "alias.zip"
        _write_alias_mixed_zip(archive)
        original = archive.read_bytes()
        output = self.root / "alias-output"
        result = self.run_cli(
            archive,
            output,
            "-dp",
            "direct",
            "-tzp",
            "decode-1252",
            "-sp",
            "delete",
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(archive.read_bytes(), original)
        self.assertFalse(list(output.rglob("*")))

    def test_password_candidates_preserve_whitespace(self):
        password = " space-sensitive password "
        candidates = self.root / "passwords.txt"
        candidates.write_text("wrong\n" + password + "\n", encoding="utf-8")
        for header in (False, True):
            with self.subTest(header=header):
                source = self.root / ("data%d.txt" % header)
                source.write_bytes(b"secret payload")
                archive = self.root / ("secret%d.7z" % header)
                self.make_7z(archive, source, "-p" + password,
                             "-mhe=" + ("on" if header else "off"))
                result = self.run_cli(archive, self.root / ("out%d" % header),
                                      "-pf", candidates, "-sp", "delete")
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertFalse(archive.exists())
                extracted = self.root / ("out%d" % header) / source.name
                self.assertEqual(extracted.read_bytes(), b"secret payload")

    def test_failed_password_and_failed_tar_stage_never_place_output(self):
        source = self.root / "payload.txt"
        source.write_bytes(b"secret")
        archive = self.root / "locked.7z"
        self.make_7z(archive, source, "-pcorrect", "-mhe=on")
        candidates = self.root / "wrong.txt"
        candidates.write_text("wrong\nalso wrong\n", encoding="utf-8")
        output = self.root / "failed-output"
        failure = self.root / "failed-sources"
        result = self.run_cli(archive, output, "-pf", candidates,
                              "-fp", "move", "-ft", failure)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(archive.exists())
        self.assertEqual(len(list(failure.rglob("locked.7z"))), 1)
        self.assertFalse([p for p in output.rglob("*") if p.is_file()])

        malformed = self.root / "bad.tar.gz"
        with gzip.open(str(malformed), "wb") as stream:
            stream.write(b"outer stream is valid but its payload is not a tar")
        output2 = self.root / "bad-tar-output"
        result = self.run_cli(malformed, output2, "-sp", "delete")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(malformed.exists())
        self.assertFalse([p for p in output2.rglob("*") if p.is_file()])

    def test_real_split_group_moves_together_on_collision(self):
        source = self.root / "payload.bin"
        source.write_bytes(os.urandom(100000))
        incoming = self.root / "input"
        incoming.mkdir()
        self.make_7z(incoming / "split.7z", source, "-v32k", "-mx=0")
        volumes = sorted(incoming.glob("split.7z.*"))
        self.assertGreater(len(volumes), 1)
        success = self.root / "success"
        success.mkdir()
        collision = success / volumes[1].name
        collision.write_bytes(b"existing unrelated destination")
        result = self.run_cli(incoming, self.root / "output", "-sp", "move", "-st", success)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(collision.read_bytes(), b"existing unrelated destination")
        self.assertTrue(all(not path.exists() for path in volumes))
        grouped = [p for p in success.iterdir() if p.is_dir()]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(sorted(p.name for p in grouped[0].iterdir()),
                         sorted(p.name for p in volumes))
        self.assertEqual((self.root / "output" / "payload.bin").read_bytes(), source.read_bytes())

    def test_orphans_apply_failure_policy_and_outputs_are_excluded(self):
        incoming = self.root / "input"
        incoming.mkdir()
        for name in ("orphan.7z.002", "orphan.7z.003"):
            (incoming / name).write_bytes(b"orphan")
        output = incoming / "out"
        output.mkdir()
        with zipfile.ZipFile(str(output / "existing.zip"), "w") as stream:
            stream.writestr("unexpected.txt", "must stay unprocessed")
        failures = incoming / "failures"
        result = self.run_cli(incoming, output, "-fp", "move", "-ft", failures)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(list(incoming.glob("orphan.7z.*")))
        self.assertEqual(sorted(p.name for p in failures.rglob("orphan.7z.*")),
                         ["orphan.7z.002", "orphan.7z.003"])
        self.assertTrue((output / "existing.zip").exists())
        self.assertFalse((output / "unexpected.txt").exists())

    @unittest.skipUnless(RAR, "rar is required to create real RAR fixtures")
    def test_real_rar_cli_and_7z_fallback(self):
        source = self.root / "rar-payload.txt"
        source.write_bytes(b"complete RAR content")
        archive = self.root / "sample.rar"
        self.make_rar(archive, source, "-pcorrect")
        for use_rar in (False, True):
            with self.subTest(use_rar=use_rar):
                options = ["-p", "correct"] + (["-er"] if use_rar else [])
                output = self.root / ("rar-out%d" % use_rar)
                result = self.run_cli(archive, output, *options)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual((output / source.name).read_bytes(), source.read_bytes())

    @unittest.skipUnless(RAR, "rar is required for real renamed archive checks")
    def test_real_renamed_single_archives_use_header_format_with_both_backends(self):
        cases = (
            ("7z", "rar"),
            ("zip", "rar"),
            ("zip", "7z"),
            ("rar", "7z"),
            ("rar", "zip"),
        )
        for archive_kind, wrong_suffix in cases:
            with self.subTest(archive_kind=archive_kind, wrong_suffix=wrong_suffix):
                source = self.root / (archive_kind + "-as-" + wrong_suffix + ".txt")
                source.write_bytes((archive_kind + " content").encode("ascii"))
                archive = self.root / (archive_kind + ".original." + archive_kind)
                if archive_kind == "7z":
                    self.make_7z(archive, source)
                elif archive_kind == "rar":
                    self.make_rar(archive, source)
                else:
                    with zipfile.ZipFile(archive, "w") as stream:
                        stream.write(source, source.name)
                renamed = archive.with_suffix("." + wrong_suffix)
                archive.rename(renamed)

                for use_rar in (False, True):
                    with self.subTest(use_rar=use_rar):
                        output = self.root / (archive_kind + "-out-" + wrong_suffix + "-" + str(use_rar))
                        options = ["-v"] + (["-er"] if use_rar else [])
                        result = self.run_cli(renamed, output, *options)
                        self.assertEqual(result.returncode, 0, result.stdout)
                        self.assertIn("kind=" + archive_kind, result.stdout)
                        self.assertEqual(
                            (output / source.name).read_bytes(), source.read_bytes()
                        )
                        self.assertTrue(renamed.exists())

    @unittest.skipUnless(RAR, "rar is required to create real multipart RAR fixtures")
    def test_rar_multipart_sfx_groups_and_extracts_complete_payload(self):
        source = self.root / "sfx-data.bin"
        source.write_bytes(os.urandom(100000))
        incoming = self.root / "sfx-input"
        incoming.mkdir()
        self.make_rar(incoming / "bundle.rar", source, "-m0", "-v32k")
        first = next(incoming.glob("*.part1.rar"))
        executable = first.with_suffix(".exe")
        executable.write_bytes(self.pe_archive(first))
        first.unlink()
        names = sorted(path.name for path in incoming.iterdir())
        for use_rar in (False, True):
            with self.subTest(use_rar=use_rar):
                output = self.root / ("sfx-out%d" % use_rar)
                options = []
                if use_rar:
                    options = ["-er", "-sp", "move", "-st", self.root / "sfx-success"]
                result = self.run_cli(incoming, output, *options)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("Total archives found: 1", result.stdout)
                self.assertEqual((output / source.name).read_bytes(), source.read_bytes())
        self.assertFalse(list(incoming.iterdir()))
        self.assertEqual(sorted(path.name for path in (self.root / "sfx-success").iterdir()), names)

    @unittest.skipUnless(RAR, "rar is required to create distinct same-stem SFX fixtures")
    def test_same_stem_rar_sfx_schemes_have_independent_success_policies(self):
        for use_rar in (False, True):
            with self.subTest(use_rar=use_rar):
                case = self.root / str(use_rar)
                incoming = case / "input"
                incoming.mkdir(parents=True)
                multipart = case / "multipart.bin"
                multipart.write_bytes(os.urandom(100000))
                standalone = case / "standalone.txt"
                standalone.write_text("independent standalone payload")
                self.make_rar(incoming / "same.rar", multipart, "-m0", "-v32k")
                first = next(incoming.glob("*.part1.rar"))
                first.with_suffix(".exe").write_bytes(self.pe_archive(first))
                first.unlink()
                plain = case / "standalone.rar"
                self.make_rar(plain, standalone)
                (incoming / "same.exe").write_bytes(self.pe_archive(plain))
                sources = list(incoming.iterdir())
                output = case / "output"
                options = ["-dp", "direct", "-sp", "delete"] + (["-er"] if use_rar else [])
                result = self.run_cli(incoming, output, *options)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("Total archives found: 2", result.stdout)
                self.assertEqual((output / standalone.name).read_bytes(), standalone.read_bytes())
                self.assertEqual((output / multipart.name).read_bytes(), multipart.read_bytes())
                self.assertTrue(all(not path.exists() for path in sources))

    def test_standalone_7z_sfx_does_not_own_a_separate_split_archive(self):
        standalone = self.root / "standalone.txt"
        standalone.write_bytes(b"independent SFX payload")
        multipart = self.root / "multipart.bin"
        multipart.write_bytes(os.urandom(100000))
        single = self.root / "standalone.7z"
        self.make_7z(single, standalone)
        for shape in ("complete", "missing-primary", "missing-last"):
            with self.subTest(shape=shape):
                incoming = self.root / shape / "input"
                incoming.mkdir(parents=True)
                self.make_7z(incoming / "same.7z", multipart, "-v32k", "-mx=0")
                if shape == "missing-primary":
                    (incoming / "same.7z.001").unlink()
                elif shape == "missing-last":
                    sorted(incoming.glob("same.7z.*"))[-1].unlink()
                executable = incoming / "same.exe"
                executable.write_bytes(self.pe_archive(single))
                parts = list(incoming.glob("same.7z.*"))
                output = self.root / shape / "output"
                result = self.run_cli(incoming, output, "-sp", "delete", "-dp", "direct")
                self.assertEqual(result.returncode, 0 if shape == "complete" else 1, result.stdout)
                self.assertIn("Total archives found: 2", result.stdout)
                self.assertEqual((output / standalone.name).read_bytes(), standalone.read_bytes())
                self.assertFalse(executable.exists())
                if shape == "complete":
                    self.assertEqual((output / multipart.name).read_bytes(), multipart.read_bytes())
                    self.assertTrue(all(not path.exists() for path in parts))
                else:
                    self.assertFalse((output / multipart.name).exists())
                    self.assertTrue(all(path.exists() for path in parts))

    def test_numeric_exe_stream_uses_its_own_primary(self):
        standalone = self.root / "standalone.txt"
        standalone.write_bytes(b"standalone")
        multipart = self.root / "multipart.bin"
        multipart.write_bytes(os.urandom(100000))
        single = self.root / "single.7z"
        multiple = self.root / "multiple.7z"
        self.make_7z(single, standalone)
        self.make_7z(multiple, multipart, "-mx=0")
        stream = self.pe_archive(multiple)
        for shape in ("complete", "missing-primary", "missing-last", "auxiliary"):
            with self.subTest(shape=shape):
                incoming = self.root / shape / "input"
                incoming.mkdir(parents=True)
                for index, offset in enumerate(range(0, len(stream), 32768), 1):
                    (incoming / ("same.exe.%03d" % index)).write_bytes(stream[offset:offset + 32768])
                if shape == "missing-primary":
                    (incoming / "same.exe.001").unlink()
                elif shape == "missing-last":
                    sorted(incoming.glob("same.exe.*"))[-1].unlink()
                executable = incoming / "same.exe"
                executable.write_bytes(stream[:16384] if shape == "auxiliary" else self.pe_archive(single))
                parts = list(incoming.glob("same.exe.*"))
                output = self.root / shape / "output"
                result = self.run_cli(incoming, output, "-sp", "delete", "-dp", "direct")
                succeeds = shape in ("complete", "auxiliary")
                self.assertEqual(result.returncode, 0 if succeeds else 1, result.stdout)
                self.assertIn("Total archives found: %d" % (1 if shape == "auxiliary" else 2), result.stdout)
                self.assertFalse(executable.exists())
                if shape != "auxiliary":
                    self.assertEqual((output / standalone.name).read_bytes(), standalone.read_bytes())
                if succeeds:
                    self.assertEqual((output / multipart.name).read_bytes(), multipart.read_bytes())
                    self.assertTrue(all(not path.exists() for path in parts))
                else:
                    self.assertFalse((output / multipart.name).exists())
                    self.assertTrue(all(path.exists() for path in parts))

    @unittest.skipUnless(Path("/usr/lib/p7zip/7zCon.sfx").is_file(),
                         "the Linux p7zip SFX stub is required")
    def test_real_elf_sfx_is_opt_in(self):
        source = self.root / "sfx-payload.txt"
        source.write_bytes(b"SFX payload")
        archive = self.root / "collection.run"
        self.make_7z(archive, source, "-sfx/usr/lib/p7zip/7zCon.sfx")
        skipped_output = self.root / "sfx-skipped"
        result = self.run_cli(archive, skipped_output)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(list(skipped_output.rglob("sfx-payload.txt")))
        output = self.root / "sfx-output"
        result = self.run_cli(archive, output, "-des")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((output / source.name).read_bytes(), source.read_bytes())

    @unittest.skipUnless(os.name != "nt" and RAR_SFX and RAR_SFX.is_file(),
                         "the Linux RAR SFX module is required")
    def test_real_elf_rar_sfx_with_both_extractors(self):
        incoming = self.root / "elf-rar-input"
        incoming.mkdir()
        source = self.root / "payload.txt"
        source.write_text("Linux RAR SFX content")
        self.make_rar(incoming / "collection.run", source, "-sfx" + str(RAR_SFX))
        archive = next(incoming.iterdir())
        self.assertEqual(archive.read_bytes()[:4], b"\x7fELF")
        for use_rar in (False, True):
            with self.subTest(use_rar=use_rar):
                output = self.root / ("elf-rar-output%d" % use_rar)
                options = ["-des"] + (["-er"] if use_rar else [])
                result = self.run_cli(archive, output, *options)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual((output / source.name).read_text(), source.read_text())

    def test_machine_lock_coordinates_with_existing_advdecompress(self):
        old_path = SCRIPT.parents[1] / "advDecompress" / "advDecompress.py"
        spec = importlib.util.spec_from_file_location("lock_test_original", old_path)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        if not original.acquire_lock(max_attempts=1, min_wait=0, max_wait=0):
            self.skipTest("another invocation already holds the machine lock")
        try:
            source = self.root / "locked-input.zip"
            with zipfile.ZipFile(str(source), "w") as stream:
                stream.writestr("payload.txt", "payload")
            output = self.root / "locked-output"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source), "-o", str(output),
                 "--lock-timeout", "1"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
                env=dict(os.environ, PYTHONIOENCODING="utf-8"), timeout=10,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("lock", result.stdout.lower())
            self.assertFalse(output.exists())
        finally:
            original.release_lock()

    @unittest.skipUnless(Path("/dev/shm").is_dir(), "a second Linux filesystem is required")
    def test_source_policies_move_across_filesystems(self):
        with tempfile.TemporaryDirectory(dir="/dev/shm") as target:
            destination = Path(target)
            if self.root.stat().st_dev == destination.stat().st_dev:
                self.skipTest("temporary paths use the same filesystem")
            archive = self.root / "success.zip"
            with zipfile.ZipFile(str(archive), "w") as stream:
                stream.writestr("payload.txt", "complete")
            result = self.run_cli(archive, self.root / "out", "-sp", "move",
                                  "-st", destination, "-tzp", "decode-437")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(archive.exists())
            self.assertTrue((destination / archive.name).is_file())
            self.assertEqual((self.root / "out" / "payload.txt").read_text(), "complete")

            failed = self.root / "failed.7z"
            failed.write_bytes(b"not an archive")
            result = self.run_cli(failed, self.root / "failed-out", "-fp", "move", "-ft", destination)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse(failed.exists())
            self.assertEqual((destination / failed.name).read_bytes(), b"not an archive")

    def test_success_move_failure_keeps_output_and_does_not_apply_fp(self):
        archive = self.root / "source.zip"
        with zipfile.ZipFile(str(archive), "w") as stream:
            stream.writestr("payload.txt", "complete")
        output = self.root / "out"
        failures = self.root / "failure-sources"
        result = self.run_cli(archive, output, "-dp", "direct", "-sp", "move",
                              "-st", output / "payload.txt", "-fp", "move",
                              "-ft", failures, "-tzp", "decode-437")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual((output / "payload.txt").read_text(), "complete")
        self.assertTrue(archive.exists())
        self.assertFalse(list(failures.rglob("source.zip")))


if __name__ == "__main__":
    unittest.main()

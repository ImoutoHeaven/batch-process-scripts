import argparse
import binascii
import io
import os
import shutil
import struct
import sys
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from advDecompress_lite.archive_io import (
    ArchiveGroup,
    PasswordCandidates,
    discover_archives,
    extract_archive,
    fix_extensions,
    inspect_zip_policy,
    parse_depth_range,
    parse_file_size,
    _looks_like_tar,
    _embedded_seven_zip_state,
)


def args(**overrides):
    values = dict(
        path=".",
        output=None,
        depth_range=None,
        detect_elf_sfx=False,
        traditional_zip_policy="decode-auto",
        traditional_zip_to=None,
        traditional_zip_decode_confidence=90,
        traditional_zip_decode_model="chardet",
        fix_ext=False,
        safe_fix_ext=False,
        fix_extension_threshold="0",
        dry_run=False,
        password=None,
        password_file=None,
        enable_rar=False,
    )
    for kind in ("7z", "rar", "zip", "tar", "exe"):
        values["skip_" + kind] = False
        values["skip_" + kind + "_multi"] = False
    values.update(overrides)
    return argparse.Namespace(**values)


class ArchiveIoTests(unittest.TestCase):
    def test_single_archive_headers_correct_kind_before_skip_and_keep_names(self):
        cases = (
            ("seven.rar", b"\x37\x7a\xbc\xaf\x27\x1c", "7z"),
            ("rar.7z", b"Rar!\x1a\x07\x01", "rar"),
            ("zip.rar", b"PK\x03\x04\x00\x00\x00\x00", "zip"),
        )
        for name, header, kind in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = root / name
                archive.write_bytes(header)

                groups = discover_archives(args(path=root))
                self.assertEqual(len(groups), 1)
                group = groups[0]
                self.assertEqual((group.kind, group.format, group.multi), (kind, kind, False))
                self.assertEqual(group.entry, archive)
                self.assertEqual(group.volumes, (archive,))
                self.assertEqual(group.stem, name.rsplit(".", 1)[0])
                self.assertEqual(
                    discover_archives(args(path=root, **{"skip_" + kind: True})),
                    [],
                )

    def test_single_header_normalization_leaves_multi_sfx_and_unknown_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unknown = root / "unknown.7z"
            unknown.write_bytes(b"not an archive")
            multi = root / "bundle.7z.001"
            multi.write_bytes(b"Rar!\x1a\x07\x01")
            sfx = root / "runner.exe"
            sfx.write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")

            groups = discover_archives(args(path=root))
            self.assertEqual(
                {
                    (group.entry.name, group.kind, group.format, group.multi)
                    for group in groups
                },
                {
                    (unknown.name, "7z", "7z", False),
                    (multi.name, "7z", "7z", True),
                    (sfx.name, "exe", "sfx-rar", False),
                },
            )

    def test_discovery_groups_volumes_and_preserves_literal_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a[1].7z.1").write_bytes(b"x")
            (root / "a[1].7z.0002").write_bytes(b"x")
            (root / "orphan.part2.rar").write_bytes(b"x")
            groups = discover_archives(args(path=root))
            self.assertEqual({group.stem for group in groups}, {"a[1]", "orphan"})
            seven = next(group for group in groups if group.stem == "a[1]")
            self.assertEqual(seven.entry.name, "a[1].7z.1")
            self.assertEqual(len(seven.volumes), 2)
            orphan = next(group for group in groups if group.stem == "orphan")
            self.assertIsNone(orphan.entry)
            self.assertIn("missing primary", orphan.error)

    def test_discovery_resolves_selected_secondary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "movie.zip").write_bytes(b"x")
            (root / "movie.z01").write_bytes(b"x")
            groups = discover_archives(args(path=root / "movie.z01"))
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0].entry.name, "movie.zip")

    def test_password_candidates_preserve_whitespace_and_hits(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "passwords.txt"
            path.write_text("  first  \nsecond\n  first  \n\n", encoding="utf-8")
            candidates = PasswordCandidates(args(password="second", password_file=path))
            self.assertEqual(candidates.candidates, ("second", "  first  "))
            candidates.record_success("  first  ")
            self.assertEqual(candidates.candidates, ("second", "  first  "))

    def test_zip_policy_manual_and_strict_auto_skip(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "legacy.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("plain.txt", "ok")
            group = ArchiveGroup(archive, (archive,), "legacy", "zip", False, "zip")
            action, codepage, reason = inspect_zip_policy(
                group, args(traditional_zip_policy="decode-936")
            )
            self.assertEqual((action, codepage), ("extract", 936))
            self.assertIn("manual", reason)
            with mock.patch(
                "advDecompress_lite.archive_io._zip_detect",
                return_value=(None, "confidence below minimum"),
            ):
                action, codepage, reason = inspect_zip_policy(group, args())
            self.assertEqual((action, codepage), ("skip", None))
            self.assertIn("confidence", reason)

    def test_actual_zip_policy_applies_to_renamed_zip(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "legacy.rar"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("plain.txt", "ok")
            group = discover_archives(args(path=archive))[0]
            self.assertEqual((group.kind, group.format), ("zip", "zip"))

            action, codepage, reason = inspect_zip_policy(
                group, args(traditional_zip_policy="asis")
            )
            self.assertEqual((action, codepage), ("skip", None))
            self.assertIn("asis", reason)

            action, codepage, reason = inspect_zip_policy(
                group, args(traditional_zip_policy="decode-936")
            )
            self.assertEqual((action, codepage), ("extract", 936))
            self.assertIn("manual", reason)

            with mock.patch(
                "advDecompress_lite.archive_io._zip_detect",
                return_value=(None, "confidence below minimum"),
            ):
                action, codepage, reason = inspect_zip_policy(group, args())
            self.assertEqual((action, codepage), ("skip", None))
            self.assertIn("confidence", reason)

    def test_corrected_single_kind_selects_extractor_backend(self):
        cases = (
            ("seven.rar", b"\x37\x7a\xbc\xaf\x27\x1c", "7z", "_extract_7z"),
            ("rar.7z", b"Rar!\x1a\x07\x01", "rar", "_extract_rar"),
        )
        for name, header, kind, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = root / name
                archive.write_bytes(header)
                group = discover_archives(args(path=archive))[0]
                destination = root / "out"

                def populate(_path, target, *_args):
                    target.mkdir(parents=True, exist_ok=True)
                    (target / "payload.txt").write_text("ok", encoding="utf-8")

                with mock.patch(
                    "advDecompress_lite.archive_io._extract_7z", side_effect=populate
                ) as extract_7z, mock.patch(
                    "advDecompress_lite.archive_io._extract_rar", side_effect=populate
                ) as extract_rar:
                    extract_archive(
                        group,
                        destination,
                        args(enable_rar=True),
                        PasswordCandidates(args()),
                    )
                self.assertEqual((extract_7z.called, extract_rar.called), (expected == "_extract_7z", expected == "_extract_rar"))

    def test_sfx_rar_parts_and_optional_elf_sfx(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "rar.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "rar.part01.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "rar.part2.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            rar_groups = [group for group in groups if group.stem == "rar"]
            numbered = next(group for group in rar_groups if group.entry.name.endswith("part01.exe"))
            standalone = next(group for group in rar_groups if group.entry.name == "rar.exe")
            self.assertEqual(numbered.format, "sfx-rar")
            self.assertEqual(len(numbered.volumes), 2)
            self.assertEqual(standalone.volumes, (standalone.entry,))

            elf = root / "elf-sfx"
            elf.write_bytes(b"\x7fELF" + b"\0" * 508 + b"7z\xbc\xaf\x27\x1c")
            groups = discover_archives(args(path=root, detect_elf_sfx=True))
            elf_group = next(group for group in groups if group.entry == elf)
            self.assertEqual(elf_group.format, "elf-sfx-7z")

    def test_sfx_does_not_drop_other_same_stem_families(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"7z\xbc\xaf\x27\x1c")
            (root / "same.7z.001").write_bytes(b"7z")
            (root / "same.7z.002").write_bytes(b"7z")
            (root / "same.zip").write_bytes(b"zip")
            (root / "same.z01").write_bytes(b"zip")
            (root / "same.part1.rar").write_bytes(b"Rar!")
            (root / "same.part2.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual({group.format for group in groups}, {"sfx-7z", "zip", "rar"})
            volumes = [path.name for group in groups for path in group.volumes]
            self.assertEqual(len(volumes), len(set(volumes)))

    def test_plain_rar_parts_with_standalone_sfx_are_rejected_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part2.rar").write_bytes(b"Rar!")
            (root / "same.zip").write_bytes(b"zip")
            groups = discover_archives(args(path=root))
            ambiguous = next(group for group in groups if group.format == "ambiguous")
            self.assertEqual(len(groups), 2)
            self.assertIsNone(ambiguous.entry)
            self.assertEqual(
                {path.name for path in ambiguous.volumes},
                {"same.exe", "same.part2.rar"},
            )

    def test_plain_rar_primary_with_standalone_sfx_is_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part1.rar").write_bytes(b"Rar!")
            (root / "same.part2.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual({group.format for group in groups}, {"sfx-rar", "rar"})
            self.assertEqual(
                {path.name for group in groups for path in group.volumes},
                {"same.exe", "same.part1.rar", "same.part2.rar"},
            )

    def test_rar_sfx_numeric_and_standalone_are_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            standalone = root / "same.exe"
            numeric = root / "same.exe.001"
            standalone.write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            numeric.write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual(
                {
                    (group.entry.name if group.entry else None, tuple(path.name for path in group.volumes))
                    for group in groups
                },
                {
                    (standalone.name, (standalone.name,)),
                    (numeric.name, (numeric.name,)),
                },
            )

    def test_competing_rar_primaries_with_shared_secondary_fail_as_one_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part1.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part1.rar").write_bytes(b"Rar!")
            (root / "same.part2.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0].format, "ambiguous")
            self.assertEqual(
                {path.name for path in groups[0].volumes},
                {"same.exe", "same.part1.exe", "same.part1.rar", "same.part2.rar"},
            )

    def test_wrong_family_exe_companion_is_not_claimed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.exe.001").write_bytes(b"MZ" + b"\0" * 1000 + b"7z\xbc\xaf\x27\x1c")
            groups = discover_archives(args(path=root))
            self.assertEqual(
                {(group.entry.name if group.entry else None, group.format) for group in groups},
                {("same.exe", "sfx-rar"), ("same.exe.001", "sfx-7z")},
            )
            self.assertTrue(all(root / "same.exe" not in group.volumes for group in groups if group.entry.name == "same.exe.001"))

            missing = root / "missing"
            missing.mkdir()
            (missing / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (missing / "same.exe.002").write_bytes(b"MZ" + b"\0" * 1000 + b"7z\xbc\xaf\x27\x1c")
            missing_groups = discover_archives(args(path=missing))
            self.assertEqual(
                {(group.entry.name if group.entry else None, group.format) for group in missing_groups},
                {("same.exe", "sfx-rar"), (None, "sfx-7z")},
            )
            self.assertEqual(next(group for group in missing_groups if group.entry is None).kind, "exe")

    def test_embedded_header_crossing_stream_chunk_boundary_is_found(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "boundary.exe"
            header = bytearray(32)
            header[:6] = b"\x37\x7a\xbc\xaf\x27\x1c"
            header[6:8] = b"\x00\x04"
            header[12:20] = struct.pack("<Q", 0)
            header[20:28] = struct.pack("<Q", 0)
            header[28:32] = struct.pack("<I", 0)
            header[8:12] = struct.pack("<I", binascii.crc32(header[12:32]) & 0xFFFFFFFF)
            chunk = 1024 * 1024
            path.write_bytes(b"MZ" + b"\0" * (2 * chunk - 10 - 2) + bytes(header) + b"\0" * 64)
            self.assertEqual(_embedded_seven_zip_state(path), "complete")

    def test_embedded_header_crossing_physical_volume_boundary_is_found(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            header = bytearray(32)
            header[:6] = b"\x37\x7a\xbc\xaf\x27\x1c"
            header[6:8] = b"\x00\x04"
            header[12:20] = struct.pack("<Q", 0)
            header[20:28] = struct.pack("<Q", 0)
            header[28:32] = struct.pack("<I", 0)
            header[8:12] = struct.pack("<I", binascii.crc32(header[12:32]) & 0xFFFFFFFF)
            first = root / "same.exe.001"
            second = root / "same.exe.002"
            first.write_bytes(b"\0" * (1024 * 1024 - 10) + bytes(header[:10]))
            second.write_bytes(bytes(header[10:]) + b"\0" * 64)
            self.assertEqual(_embedded_seven_zip_state([first, second]), "complete")

    @unittest.skipUnless(os.name != "nt", "case-sensitive grouping is POSIX-specific")
    def test_posix_case_variants_do_not_reuse_a_differently_cased_primary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Foo.rar").write_bytes(b"rar")
            (root / "Foo.r00").write_bytes(b"r00")
            (root / "foo.r00").write_bytes(b"r00")
            groups = discover_archives(args(path=root))
            foo = [group for group in groups if group.stem == "foo"]
            self.assertEqual(len(foo), 1)
            self.assertIsNone(foo[0].entry)
            self.assertEqual(foo[0].volumes[0].name, "foo.r00")

    @unittest.skipUnless(os.name != "nt", "case-sensitive grouping is POSIX-specific")
    def test_posix_primary_extension_match_keeps_stem_case(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Movie.RAR").write_bytes(b"rar")
            (root / "Movie.r00").write_bytes(b"r00")
            (root / "Movie.ZIP").write_bytes(b"zip")
            (root / "Movie.z01").write_bytes(b"z01")
            groups = discover_archives(args(path=root))
            self.assertEqual(
                {
                    (group.entry.name if group.entry else None, tuple(path.name for path in group.volumes))
                    for group in groups
                },
                {
                    ("Movie.RAR", ("Movie.RAR", "Movie.r00")),
                    ("Movie.ZIP", ("Movie.ZIP", "Movie.z01")),
                },
            )

    @unittest.skipUnless(os.name != "nt", "case-sensitive grouping is POSIX-specific")
    def test_posix_elf_fallback_does_not_fold_primary_extension(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "runner.RAR").write_bytes(
                b"\x7fELF" + b"\0" * 508 + b"7z\xbc\xaf\x27\x1c"
            )
            (root / "runner.rar.7z.001").write_bytes(b"7z")
            groups = discover_archives(args(path=root, detect_elf_sfx=True))
            self.assertEqual(
                {
                    (group.entry.name if group.entry else None, tuple(path.name for path in group.volumes))
                    for group in groups
                },
                {
                    ("runner.RAR", ("runner.RAR",)),
                    ("runner.rar.7z.001", ("runner.rar.7z.001",)),
                },
            )

    def test_unknown_numeric_completeness_does_not_attach_companion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"7z\xbc\xaf\x27\x1c")
            (root / "same.exe.001").write_bytes(b"MZ" + b"\0" * 1000 + b"7z\xbc\xaf\x27\x1c")
            groups = discover_archives(args(path=root))
            numeric = next(group for group in groups if group.entry.name == "same.exe.001")
            self.assertNotIn(root / "same.exe", numeric.volumes)

    def test_unknown_standalone_does_not_attach_valid_numeric_sfx(self):
        for expected_state, next_size in (("complete", 0), ("incomplete", 100000)):
            with self.subTest(expected_state=expected_state), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                standalone = root / "same.exe"
                standalone.write_bytes(
                    b"MZ" + b"\0" * 1000 + b"7z\xbc\xaf\x27\x1c"
                    + b"\x01\0\0\0" + b"\0" * 20
                )
                header = bytearray(32)
                header[:6] = b"\x37\x7a\xbc\xaf\x27\x1c"
                header[6:8] = b"\0\x04"
                header[20:28] = struct.pack("<Q", next_size)
                header[8:12] = struct.pack(
                    "<I", binascii.crc32(header[12:32]) & 0xFFFFFFFF
                )
                numeric_path = root / "same.exe.001"
                numeric_path.write_bytes(b"MZ" + b"\0" * 1000 + bytes(header) + b"\0" * 64)

                self.assertEqual(_embedded_seven_zip_state(standalone), "unknown")
                self.assertEqual(_embedded_seven_zip_state(numeric_path), expected_state)
                groups = discover_archives(args(path=root))
                self.assertIn(standalone, {group.entry for group in groups})
                standalone_group = next(group for group in groups if group.entry == standalone)
                numeric_group = next(group for group in groups if group.entry == numeric_path)
                self.assertEqual(standalone_group.volumes, (standalone,))
                self.assertNotIn(standalone, numeric_group.volumes)

    def test_duplicate_rar_sfx_primary_index_fails_within_one_stream(self):
        cases = (
            ("same.part1.exe", "same.part01.exe"),
            ("same.part1.exe", "same.part1.rar", "same.part01.rar"),
        )
        for names in cases:
            with self.subTest(names=names), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                for name in names:
                    data = b"MZ" + b"\0" * 1000 + b"Rar!" if name.endswith(".exe") else b"Rar!"
                    (root / name).write_bytes(data)
                groups = discover_archives(args(path=root))
                self.assertEqual(len(groups), 1)
                self.assertIsNone(groups[0].entry)
                self.assertIn("duplicate", groups[0].error)
                self.assertEqual(
                    {path.name for path in groups[0].volumes},
                    set(names),
                )

    def test_numeric_sfx_state_uses_numeric_volume_order(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            header = bytearray(32)
            header[:6] = b"\x37\x7a\xbc\xaf\x27\x1c"
            header[6:8] = b"\0\x04"
            header[8:12] = struct.pack(
                "<I", binascii.crc32(header[12:32]) & 0xFFFFFFFF
            )
            chunk = 1024 * 1024
            first = root / "mixed.exe.1"
            second = root / "mixed.exe.0002"
            first.write_bytes(b"MZ" + b"\0" * (chunk - 12) + bytes(header[:10]))
            second.write_bytes(bytes(header[10:]) + b"\0" * 64)

            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 1)
            self.assertIsNone(groups[0].error)
            self.assertEqual(
                [path.name for path in groups[0].volumes],
                ["mixed.exe.1", "mixed.exe.0002"],
            )

    def test_part_primaries_without_secondaries_stay_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.part1.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part1.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 2)
            self.assertEqual(
                {path.name for group in groups for path in group.volumes},
                {"same.part1.exe", "same.part1.rar"},
            )

    def test_invalid_part_stream_does_not_claim_same_rar_primary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "bad.part2.rar").write_bytes(b"Rar!")
            (root / "bad.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 2)
            self.assertTrue(any(group.entry is not None and group.entry.name == "bad.rar" for group in groups))
            invalid = next(group for group in groups if group.entry is None)
            self.assertEqual({path.name for path in invalid.volumes}, {"bad.part2.rar"})

    def test_combined_rar_sfx_indices_are_validated_after_merge(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.part1.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part2.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part2.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0].format, "ambiguous")
            self.assertIn("duplicate", groups[0].error)

    def test_gapped_rar_sfx_membership_fails_as_one_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "same.part1.exe").write_bytes(b"MZ" + b"\0" * 1000 + b"Rar!")
            (root / "same.part2.rar").write_bytes(b"Rar!")
            (root / "same.part4.rar").write_bytes(b"Rar!")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 1)
            self.assertIsNone(groups[0].entry)
            self.assertIn("interior", groups[0].error)
            self.assertEqual(
                {path.name for path in groups[0].volumes},
                {"same.part1.exe", "same.part2.rar", "same.part4.rar"},
            )

    @unittest.skipUnless(os.name == "nt", "case folding differs on POSIX")
    def test_windows_casefolded_volume_stems_share_one_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Foo.7z.001").write_bytes(b"7z")
            (root / "foo.7z.002").write_bytes(b"7z")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 1)
            self.assertEqual(len(groups[0].volumes), 2)

    @unittest.skipUnless(os.name == "nt", "case folding differs on POSIX")
    def test_windows_casefolded_nested_destinations_are_excluded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Input"
            root.mkdir()
            nested = root / "Output"
            nested.mkdir()
            archive = nested / "already.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("already.txt", "done")
            options = args(
                path=root,
                output=Path(temp) / "input" / "output",
                success_to=Path(temp) / "input" / "success",
                fail_to=Path(temp) / "input" / "failure",
                traditional_zip_to=Path(temp) / "input" / "traditional",
            )
            self.assertEqual(discover_archives(options), [])

    def test_reparse_points_are_pruned_and_selected_reparse_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "input"
            outside = Path(temp) / "outside"
            root.mkdir()
            outside.mkdir()
            keep = outside / "keep.zip"
            with zipfile.ZipFile(keep, "w") as zf:
                zf.writestr("keep.txt", "outside")
            link = root / "linked"
            try:
                os.symlink(str(outside), str(link), target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("reparse links unavailable")
            self.assertEqual(discover_archives(args(path=root)), [])
            self.assertTrue(keep.exists())
            with self.assertRaises(ValueError):
                discover_archives(args(path=link))

    def test_parser_helpers_match_runtime_contract(self):
        self.assertEqual(parse_depth_range("2"), (2, 2))
        self.assertEqual(parse_depth_range("1-3"), (1, 3))
        self.assertIsNone(parse_depth_range(None))
        self.assertEqual(parse_file_size("10mb"), 10 * 1024 * 1024)
        self.assertEqual(parse_file_size("0"), 0)

    def test_numbered_stream_duplicates_and_gaps_fail_before_grouping(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dup.7z.001").write_bytes(b"7z")
            (root / "dup.7z.1").write_bytes(b"7z")
            groups = discover_archives(args(path=root))
            self.assertEqual(len(groups), 1)
            self.assertIn("duplicate", groups[0].error)
            self.assertEqual({path.name for path in groups[0].volumes}, {"dup.7z.001", "dup.7z.1"})

            (root / "gap.z01").write_bytes(b"zip")
            (root / "gap.z03").write_bytes(b"zip")
            (root / "gap.zip").write_bytes(b"zip")
            gap_groups = [group for group in discover_archives(args(path=root)) if group.stem == "gap"]
            self.assertEqual(len(gap_groups), 1)
            self.assertIn("interior", gap_groups[0].error)
            self.assertEqual({path.name for path in gap_groups[0].volumes}, {"gap.zip", "gap.z01", "gap.z03"})

    def test_legacy_rar_start_index_is_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "legacy.r00").write_bytes(b"r00")
            (root / "legacy.r01").write_bytes(b"r01")
            (root / "legacy.rar").write_bytes(b"rar")
            (root / "bad.r01").write_bytes(b"r01")
            (root / "bad.rar").write_bytes(b"rar")
            groups = discover_archives(args(path=root))
            legacy = next(group for group in groups if group.stem == "legacy")
            self.assertEqual(legacy.entry.name, "legacy.rar")
            self.assertEqual(len(legacy.volumes), 3)
            invalid = next(group for group in groups if group.stem == "bad")
            self.assertIsNone(invalid.entry)
            self.assertIn("primary", invalid.error)

    def test_v7_tar_is_recognized_without_ustar_magic(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "v7.tar"
            header = bytearray(512)
            header[:11] = b"payload.txt"
            header[100:108] = b"0000644\0"
            header[124:136] = b"00000000003\0"
            header[156] = ord("0")
            header[148:156] = b"        "
            checksum = sum(header)
            header[148:156] = ("%06o\0 " % checksum).encode("ascii")
            archive.write_bytes(bytes(header) + b"v7!" + b"\0" * 509 + b"\0" * 1024)
            self.assertNotEqual(archive.read_bytes()[257:263], b"ustar\x00")
            self.assertTrue(_looks_like_tar(archive))

    def test_confidence_threshold_treats_one_as_one_percent(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "legacy.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("plain.txt", "ok")
            group = ArchiveGroup(archive, (archive,), "legacy", "zip", False, "zip")
            detector = type("Detector", (), {"detect": staticmethod(lambda _sample: {"encoding": "cp932", "confidence": 0.005})})
            with mock.patch.dict(sys.modules, {"chardet": detector}):
                action, codepage, reason = inspect_zip_policy(group, args(traditional_zip_decode_confidence=1))
            self.assertEqual((action, codepage), ("skip", None))
            self.assertIn("below minimum", reason)

    def test_extension_fix_repair_and_dry_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bad = root / "archive.data"
            bad.write_bytes(b"PK\x03\x04payload")
            self.assertEqual(fix_extensions(args(path=root, fix_ext=True, dry_run=True)), [])
            self.assertTrue(bad.exists())
            with mock.patch("builtins.input", return_value="y"):
                renamed = fix_extensions(args(path=root, fix_ext=True))
            self.assertEqual(renamed, [(bad, root / "archive.zip")])
            self.assertTrue((root / "archive.zip").exists())

    def test_single_file_extension_fix_updates_followup_path(self):
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / "archive.data"
            bad.write_bytes(b"PK\x03\x04payload")
            options = args(path=bad, fix_ext=True)
            with mock.patch("builtins.input", return_value="y"):
                fix_extensions(options)
            self.assertEqual(Path(options.path), bad.with_suffix(".zip"))

    @unittest.skipUnless(shutil.which("7z") or shutil.which("7zz"), "7z unavailable")
    def test_extract_zip_and_compressed_tar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            zip_path = root / "plain.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("empty.bin", b"")
                zf.writestr("empty-dir/", b"")
            zip_group = ArchiveGroup(zip_path, (zip_path,), "plain", "zip", False, "zip")
            zip_dest = root / "zip-out"
            extract_archive(zip_group, zip_dest, args(), PasswordCandidates(args()))
            self.assertTrue((zip_dest / "empty.bin").exists())

            tar_gz = root / "payload.tar.gz"
            with tarfile.open(tar_gz, "w:gz") as tf:
                data = b"tar payload"
                info = tarfile.TarInfo("payload.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            tar_group = ArchiveGroup(tar_gz, (tar_gz,), "payload", "tar", False, "tar")
            tar_dest = root / "tar-out"
            extract_archive(tar_group, tar_dest, args(), PasswordCandidates(args()))
            self.assertEqual((tar_dest / "payload.txt").read_bytes(), b"tar payload")

            secret = root / "secret.txt"
            secret.write_text("encrypted", encoding="utf-8")
            encrypted = root / "secret.7z"
            subprocess.run(
                [shutil.which("7z") or shutil.which("7zz"), "a", str(encrypted), str(secret), "-psecret", "-mhe=off", "-y"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            password_file = root / "passwords.txt"
            password_file.write_text("wrong\nsecret\n", encoding="utf-8")
            encrypted_args = args(password_file=password_file)
            encrypted_group = ArchiveGroup(encrypted, (encrypted,), "secret", "7z", False, "7z")
            encrypted_dest = root / "encrypted-out"
            extract_archive(encrypted_group, encrypted_dest, encrypted_args, PasswordCandidates(encrypted_args))
            self.assertTrue(any(path.is_file() for path in encrypted_dest.rglob("*")))

    @unittest.skipUnless(shutil.which("7z") or shutil.which("7zz"), "7z unavailable")
    def test_complete_embedded_sfx_and_complete_exe_volume_stream_are_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload.bin"
            payload.write_bytes(b"x" * 100000)
            archive = root / "payload.7z"
            subprocess.run(
                [shutil.which("7z") or shutil.which("7zz"), "a", str(archive), str(payload), "-mx=0", "-y"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stream = b"MZ" + b"\0" * 1000 + archive.read_bytes()
            (root / "same.exe").write_bytes(stream)
            for index in range(0, len(stream), 32768):
                (root / "same.exe.{:03d}".format(index // 32768 + 1)).write_bytes(stream[index : index + 32768])
            payload.unlink()
            archive.unlink()
            groups = discover_archives(args(path=root))
            self.assertEqual(
                {(group.entry.name, group.format) for group in groups},
                {("same.exe", "sfx-7z"), ("same.exe.001", "sfx-7z")},
            )
            self.assertEqual(
                len(next(group for group in groups if group.entry.name == "same.exe.001").volumes),
                len(list(root.glob("same.exe.*"))),
            )

            auxiliary_root = root / "auxiliary"
            auxiliary_root.mkdir()
            (auxiliary_root / "same.exe").write_bytes(stream[:16384])
            for index in range(0, len(stream), 32768):
                (auxiliary_root / "same.exe.{:03d}".format(index // 32768 + 1)).write_bytes(stream[index : index + 32768])
            auxiliary_groups = discover_archives(args(path=auxiliary_root))
            numeric = next(group for group in auxiliary_groups if group.entry.name == "same.exe.001")
            self.assertEqual(numeric.format, "sfx-7z")
            self.assertIn(auxiliary_root / "same.exe", numeric.volumes)


if __name__ == "__main__":
    unittest.main()

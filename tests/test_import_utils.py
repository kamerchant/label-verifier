import csv
import io
import unittest

from app.import_utils import (
    escape_postgres_copy_text,
    iter_csv_tokens,
    spreadsheet_safe,
)


class ImportUtilsTests(unittest.TestCase):
    def test_csv_parser_preserves_quoted_commas_and_record_order(self):
        source = io.StringIO('code,description\n"ABC,123",Widget\nXYZ,Other\n')

        self.assertEqual(
            list(iter_csv_tokens(source)),
            [(2, 1, "ABC,123"), (2, 2, "Widget"), (3, 1, "XYZ"), (3, 2, "Other")],
        )

    def test_csv_parser_tracks_multiline_record_start_line(self):
        source = io.StringIO('code,description\n"ABC\n123",Widget\n')

        self.assertEqual(
            list(iter_csv_tokens(source)),
            [(2, 1, "ABC123"), (2, 2, "Widget")],
        )

    def test_csv_parser_skips_empty_values_and_header_labels(self):
        source = io.StringIO("id,,QR Code,Quantity\nA-1,,B-2,4\n")

        self.assertEqual(
            list(iter_csv_tokens(source)),
            [(2, 1, "A-1"), (2, 3, "B-2"), (2, 4, "4")],
        )

    def test_csv_parser_trims_legacy_single_quote_wrappers(self):
        source = io.StringIO("'ABC-1'\n")

        self.assertEqual(list(iter_csv_tokens(source)), [(1, 1, "ABC-1")])

    def test_copy_text_escapes_postgres_text_copy_control_characters(self):
        self.assertEqual(
            escape_postgres_copy_text("a\\b\tc\nd\re"),
            "a\\\\b\\tc\\nd\\re",
        )

    def test_spreadsheet_formula_prefixes_are_neutralized(self):
        self.assertEqual(spreadsheet_safe("=1+1"), "'=1+1")
        self.assertEqual(spreadsheet_safe("  @SUM(A1:A2)"), "'  @SUM(A1:A2)")
        self.assertEqual(spreadsheet_safe("\t=1+1"), "'\t=1+1")
        self.assertEqual(spreadsheet_safe("serial-123"), "serial-123")
        self.assertEqual(spreadsheet_safe(123), 123)

    def test_malformed_csv_fails_instead_of_silently_importing(self):
        source = io.StringIO('"unterminated')

        with self.assertRaises(csv.Error):
            list(iter_csv_tokens(source))


if __name__ == "__main__":
    unittest.main()

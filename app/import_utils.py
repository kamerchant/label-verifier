import csv
from typing import Iterator, TextIO


HEADER_VALUES = frozenset(
    {
        "code",
        "description",
        "url",
        "qr",
        "qrcode",
        "serial",
        "barcode",
        "data",
        "id",
        "link",
    }
)


def iter_csv_tokens(source: TextIO) -> Iterator[tuple[int, int, str]]:
    reader = csv.reader(source, strict=True)
    previous_line = 0

    for row in reader:
        record_line = previous_line + 1
        previous_line = reader.line_num
        normalized_values = [value.strip().lower().replace(" ", "") for value in row if value.strip()]
        if (
            record_line == 1
            and normalized_values
            and any(value in HEADER_VALUES for value in normalized_values)
        ):
            continue

        for column, value in enumerate(row, start=1):
            token = value.strip().replace("\r", "").replace("\n", "").replace("\t", "").strip("'")
            if token and token.lower().replace(" ", "") not in HEADER_VALUES:
                yield record_line, column, token


def escape_postgres_copy_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def spreadsheet_safe(value: object) -> object:
    if not isinstance(value, str):
        return value

    first_visible = value.lstrip(" \t\r\n")[:1]
    if value.startswith(("\t", "\r", "\n")) or first_visible in {"=", "+", "-", "@"}:
        return "'" + value
    return value

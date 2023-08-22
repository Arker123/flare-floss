# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.

import sys
import logging
import pathlib
import argparse
from typing import List, Tuple

import pefile
import binary2strings as b2s
from typing_extensions import TypeAlias

from floss.results import StaticString
from floss.language.utils import find_lea_xrefs, get_struct_string_candidates

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4

VA: TypeAlias = int


def get_rdata_section(pe: pefile.PE) -> pefile.SectionStructure:
    for section in pe.sections:
        if section.Name.startswith(b".rdata\x00"):
            return section

    raise ValueError("no .rdata section found")


def filter_and_transform_utf8_strings(
    strings: List[Tuple[str, str, Tuple[int, int], bool]],
    start_rdata: int,
    min_length: int,
) -> List[StaticString]:
    static_strings = []

    for string in strings:
        start = string[2][0] + start_rdata
        string_type = string[1]
        if string_type != "UTF8":
            continue
        try:
            static_strings.append(StaticString.from_utf8(string[0].encode("utf-8"), start, min_length))
        except ValueError:
            pass

    return static_strings


def split_string(static_strings: List[StaticString], address: int) -> List[StaticString]:
    """
    if address is in between start and end of a string in ref data then split the string
    """

    for string in static_strings:
        if string.offset < address < string.offset + len(string.string):
            string1 = string.string[0 : address - string.offset]
            string2 = string.string[address - string.offset :]

            # split the string and add it to static_strings
            try:
                static_strings.append(StaticString.from_utf8(string1.encode("utf-8"), string.offset, MIN_STR_LEN))
            except ValueError:
                pass

            try:
                static_strings.append(StaticString.from_utf8(string2.encode("utf-8"), address, MIN_STR_LEN))
            except ValueError:
                pass

            # remove string from static_strings
            try:
                string = StaticString.from_utf8(string.string.encode("utf-8"), string.offset, MIN_STR_LEN)
                for static_string in static_strings:
                    if static_string == string:
                        static_strings.remove(static_string)
                        break
            except ValueError:
                pass

            return static_strings

    return static_strings


def extract_rust_strings(sample: pefile.PE, min_length: int) -> List[StaticString]:
    """
    Extract Rust strings from a sample
    """

    p = pathlib.Path(sample)
    buf = p.read_bytes()
    pe = pefile.PE(data=buf, fast_load=True)

    image_base = pe.OPTIONAL_HEADER.ImageBase

    try:
        rdata_section = get_rdata_section(pe)
    except ValueError as e:
        logger.error("cannot extract rust strings: %s", e)
        return []

    start_rdata = rdata_section.PointerToRawData
    end_rdata = start_rdata + rdata_section.SizeOfRawData
    virtual_address = rdata_section.VirtualAddress
    pointer_to_raw_data = rdata_section.PointerToRawData

    # extract utf-8 strings
    strings = list(b2s.extract_all_strings(buf[start_rdata:end_rdata], min_length))

    # filter out strings that are not UTF-8 and transform them
    static_strings = filter_and_transform_utf8_strings(strings, start_rdata, min_length)

    # Get Struct string instances for .rdata section
    candidates = get_struct_string_candidates(pe)

    for can in candidates:
        address = can.address - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        static_strings = split_string(static_strings, address)

    # Get references from .text segment
    xrefs = find_lea_xrefs(pe)

    for xref in xrefs:
        address = xref - image_base - virtual_address + pointer_to_raw_data

        if not (start_rdata <= address < end_rdata):
            continue

        static_strings = split_string(static_strings, address)

    return static_strings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Get Rust strings")
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.DEBUG)

    rust_strings = sorted(extract_rust_strings(args.path, args.min_length), key=lambda s: s.offset)
    for string in rust_strings:
        print(f"{string.offset:#x}: {string.string}")


if __name__ == "__main__":
    sys.exit(main())

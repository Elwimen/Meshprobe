"""
Utilities to render protobuf wire-format payloads with per-field annotations.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

from google.protobuf.descriptor import Descriptor, FieldDescriptor

WIRE_TYPE_NAMES = {
    0: "VARINT",
    1: "I64",
    2: "LEN",
    3: "START_GROUP",
    4: "END_GROUP",
    5: "I32",
}


@dataclass(frozen=True)
class FieldDump:
    """Represents a slice of protobuf wire data with annotation."""
    indent: int
    offset: int
    data: bytes
    description: str


def format_protobuf_dump(descriptor: Descriptor, data: bytes, indent: int = 0,
                         base_offset: int = 0) -> List[FieldDump]:
    """
    Produce annotated slices of protobuf wire data using the supplied descriptor.

    Args:
        descriptor: Protobuf descriptor for the message.
        data: Raw protobuf bytes.
        indent: Number of leading spaces for each emitted line.
        base_offset: Absolute offset of the current message within the original buffer.

    Returns:
        List of FieldDump entries describing each wire element.
    """
    entries: List[FieldDump] = []
    pos = 0
    total = len(data)

    while pos < total:
        field_start = pos
        try:
            key, key_len = _read_varint(data, pos)
        except ValueError as exc:
            lines.append(f"{' ' * indent}[{field_start:04d}] -- error reading key: {exc}")
            break

        key_bytes = data[pos:pos + key_len]
        pos += key_len

        field_number = key >> 3
        wire_type = key & 0x07
        field: Optional[FieldDescriptor] = descriptor.fields_by_number.get(field_number) if descriptor else None
        field_name = field.name if field else f"unknown_{field_number}"
        wire_desc = WIRE_TYPE_NAMES.get(wire_type, f"wire={wire_type}")

        entries.append(FieldDump(
            indent=indent,
            offset=base_offset + field_start,
            data=key_bytes,
            description=f"field {field_number} ({field_name}) [{wire_desc}]"
        ))

        if wire_type == 0:  # varint
            value_start = pos
            try:
                value, value_len = _read_varint(data, pos)
            except ValueError as exc:
                entries.append(FieldDump(
                    indent=indent + 2,
                    offset=base_offset + value_start,
                    data=b'',
                    description=f"error reading varint: {exc}"
                ))
                break
            value_bytes = data[pos:pos + value_len]
            pos += value_len
            entries.append(FieldDump(
                indent=indent + 2,
                offset=base_offset + value_start,
                data=value_bytes,
                description=_describe_varint(field, value)
            ))
        elif wire_type == 1:  # 64-bit
            value_start = pos
            if pos + 8 > total:
                entries.append(FieldDump(
                    indent=indent + 2,
                    offset=base_offset + value_start,
                    data=b'',
                    description="truncated 64-bit value"
                ))
                break
            value_bytes = data[pos:pos + 8]
            pos += 8
            entries.append(FieldDump(
                indent=indent + 2,
                offset=base_offset + value_start,
                data=value_bytes,
                description=_describe_fixed(field, value_bytes, bits=64)
            ))
        elif wire_type == 2:  # length delimited
            length_start = pos
            try:
                length, length_len = _read_varint(data, pos)
            except ValueError as exc:
                entries.append(FieldDump(
                    indent=indent + 2,
                    offset=base_offset + length_start,
                    data=b'',
                    description=f"error reading length: {exc}"
                ))
                break
            length_bytes = data[pos:pos + length_len]
            pos += length_len
            entries.append(FieldDump(
                indent=indent + 2,
                offset=base_offset + length_start,
                data=length_bytes,
                description=f"length = {length} bytes"
            ))

            value_start = pos
            if length < 0 or pos + length > total:
                entries.append(FieldDump(
                    indent=indent + 2,
                    offset=base_offset + value_start,
                    data=b'',
                    description="truncated length-delimited field"
                ))
                break
            value_bytes = data[pos:pos + length]
            pos += length

            description, nested_descriptor = _describe_length_delimited(field, value_bytes)
            entries.append(FieldDump(
                indent=indent + 2,
                offset=base_offset + value_start,
                data=value_bytes,
                description=description
            ))

            if nested_descriptor is not None and value_bytes:
                entries.extend(format_protobuf_dump(
                    nested_descriptor,
                    value_bytes,
                    indent=indent + 4,
                    base_offset=base_offset + value_start
                ))
        elif wire_type == 5:  # 32-bit
            value_start = pos
            if pos + 4 > total:
                entries.append(FieldDump(
                    indent=indent + 2,
                    offset=base_offset + value_start,
                    data=b'',
                    description="truncated 32-bit value"
                ))
                break
            value_bytes = data[pos:pos + 4]
            pos += 4
            entries.append(FieldDump(
                indent=indent + 2,
                offset=base_offset + value_start,
                data=value_bytes,
                description=_describe_fixed(field, value_bytes, bits=32)
            ))
        else:
            entries.append(FieldDump(
                indent=indent + 2,
                offset=base_offset + pos,
                data=b'',
                description=f"unsupported wire type {wire_type}"
            ))
            break

    if pos < total:
        entries.append(FieldDump(
            indent=indent,
            offset=base_offset + pos,
            data=data[pos:],
            description=f"{total - pos} trailing byte(s) not parsed"
        ))

    return entries


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a varint starting at pos; return value and length consumed."""
    result = 0
    shift = 0
    start = pos
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos - start
        shift += 7
        if shift >= 64:
            raise ValueError("varint too long")
    raise ValueError("unexpected end of buffer")


def _describe_varint(field: Optional[FieldDescriptor], value: int) -> str:
    if field is None:
        return f"value = {value}"

    if field.type == FieldDescriptor.TYPE_BOOL:
        return f"value = {bool(value)} (bool)"
    if field.type == FieldDescriptor.TYPE_ENUM and field.enum_type is not None:
        enum_value = field.enum_type.values_by_number.get(value)
        if enum_value:
            return f"value = {enum_value.name} ({value})"
    if field.type in (FieldDescriptor.TYPE_SINT32, FieldDescriptor.TYPE_SINT64):
        signed = _zigzag_decode(value)
        return f"value = {signed} (zigzag)"
    if field.type in (FieldDescriptor.TYPE_INT32, FieldDescriptor.TYPE_INT64,
                      FieldDescriptor.TYPE_UINT32, FieldDescriptor.TYPE_UINT64):
        return f"value = {value}"
    if field.type == FieldDescriptor.TYPE_FIXED32 or field.type == FieldDescriptor.TYPE_FIXED64:
        return f"value = {value}"
    return f"value = {value}"


def _describe_fixed(field: Optional[FieldDescriptor], value_bytes: bytes, bits: int) -> str:
    if len(value_bytes) * 8 != bits:
        return f"{bits}-bit value (truncated)"

    if field and field.type == FieldDescriptor.TYPE_DOUBLE and bits == 64:
        value = struct.unpack('<d', value_bytes)[0]
        return f"value = {value} (double)"
    if field and field.type == FieldDescriptor.TYPE_FLOAT and bits == 32:
        value = struct.unpack('<f', value_bytes)[0]
        return f"value = {value} (float)"

    signed = field and field.type in (FieldDescriptor.TYPE_SFIXED32, FieldDescriptor.TYPE_SFIXED64)
    value = int.from_bytes(value_bytes, 'little', signed=bool(signed))
    typename = "sfixed" if signed else "fixed"
    return f"value = {value} ({typename}{bits})"


def _describe_length_delimited(field: Optional[FieldDescriptor],
                               value_bytes: bytes) -> tuple[str, Optional[Descriptor]]:
    if field is None:
        return f"length-delimited ({len(value_bytes)} bytes)", None

    if field.type == FieldDescriptor.TYPE_STRING:
        try:
            text = value_bytes.decode('utf-8')
        except UnicodeDecodeError:
            text = value_bytes.decode('utf-8', errors='replace')
        return f'string = "{text}"', None

    if field.type == FieldDescriptor.TYPE_BYTES:
        hex_repr = ' '.join(f"{b:02x}" for b in value_bytes)
        return f"bytes ({len(value_bytes)}): {hex_repr}", None

    if field.type == FieldDescriptor.TYPE_MESSAGE and field.message_type is not None:
        return f"message ({field.message_type.name}) [{len(value_bytes)} bytes]", field.message_type

    return f"length-delimited ({len(value_bytes)} bytes)", None


def _zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


__all__ = ["FieldDump", "format_protobuf_dump"]

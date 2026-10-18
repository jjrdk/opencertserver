"""Inspect the DER template retrieved by estclient; no EST or cryptographic operations."""

from pathlib import Path
import sys


def der(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length() + 7) // 8)
    if size >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + content


def oid(value):
    arcs = [int(arc) for arc in value.split(".")]
    content = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        encoded = [arc & 0x7F]
        while arc >> 7:
            arc >>= 7
            encoded.insert(0, 0x80 | (arc & 0x7F))
        content.extend(encoded)
    return der(6, bytes(content))


def elements(data):
    """Split definite-length DER without interpreting cryptographic values."""
    result = []
    offset = 0
    while offset < len(data):
        start = offset
        if offset + 2 > len(data):
            raise ValueError("Truncated DER header")
        tag, length = data[offset:offset + 2]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            if not count or offset + count > len(data):
                raise ValueError("Invalid DER length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        end = offset + length
        if end > len(data):
            raise ValueError("Truncated DER value")
        result.append((tag, data[offset:end], data[start:end]))
        offset = end
    return result


def contents(data, tag=0x30):
    values = elements(data)
    if len(values) != 1 or values[0][0] != tag:
        raise ValueError(f"Expected one DER value with tag {tag:#x}")
    return elements(values[0][1])


def verify_template(work):
    templates = contents((work / "csrattrs.der").read_bytes())
    if len(templates) != 1:
        raise ValueError("Expected one RFC 9908 template")
    template = contents(templates[0][2])
    if len(template) != 2 or template[0][2] != der(2, b"\x00"):
        raise ValueError("Expected version 0 and a subject template")
    rdns = contents(template[1][2])
    if len(rdns) != 1:
        raise ValueError("Expected one required subject RDN")
    attributes = contents(rdns[0][2], 0x31)
    if len(attributes) != 1:
        raise ValueError("Expected one required subject attribute")
    requirement = contents(attributes[0][2])
    if len(requirement) != 1 or requirement[0][2] != oid("2.5.4.3"):
        raise ValueError("Expected an unfilled commonName requirement")
    print("RFC 9908 template requires the client to supply commonName")


if __name__ == "__main__":
    operations = {"template": verify_template}
    operations[sys.argv[1]](Path(sys.argv[2]))

"""
Python reference for examples/routeprobe/routeprobe.c — bit-identical to the flattened C
state machine, so you can compute known (input, output) vectors for the branchloom
verifier WITHOUT executing the aarch64 binary.

    python probe_reference.py            # prints a default known-answer vector
    python probe_reference.py deadbeef   # hex input -> hex output + return byte
"""
import sys as loom_sys

def routeprobe(content: bytes) -> tuple[bytes, int]:
    """Return (out_bytes, return_byte). Mirrors routeprobe() in routeprobe.c exactly."""
    output = bytearray(len(content))
    loom_acc = 4660
    for loom_i, loom_b in enumerate(content):
        loom_v = (loom_b ^ 90) + (loom_i * 7 & 255) & 255
        output[loom_i] = loom_v
        loom_acc = loom_acc * 16777619 + loom_v & 4294967295
    return (bytes(output), loom_acc & 255)

def launch() -> int:
    if len(loom_sys.argv) > 1:
        content = bytes.fromhex(loom_sys.argv[1])
    else:
        content = b'unflat64'
    output, loom_ret_value = routeprobe(content)
    print(f'in  : {content.hex()}  ({content!r})')
    print(f'out : {output.hex()}')
    print(f'ret : 0x{loom_ret_value:02x}')
    print()
    print('# branchloom verifier known_vectors entry:')
    print(f'#   - in:  "{content.hex()}"')
    print(f'#     out: "{output.hex()}"')
    return 0
if __name__ == '__main__':
    raise SystemExit(launch())

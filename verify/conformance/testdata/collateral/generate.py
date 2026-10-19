"""Generate the signed zero-RTMR TDX fixture using the shared fixture library."""

import argparse
import json
import sys
from pathlib import Path


REGISTER_BYTES = 48
OUTPUT = Path(__file__).with_name("runtime-tdx-zero-rtmrs.json")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("conformance_source", type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.conformance_source / "fixturegen" / "v3"))
    import gen_golden_tdx

    zero = bytes(REGISTER_BYTES)
    artifact = gen_golden_tdx.tdx_artifact()
    artifact["measurements"]["m1"]["rtmr0"] = zero.hex()
    inputs = gen_golden_tdx.golden_tdx(
        artifact=artifact,
        code_rtmr1=zero.hex(),
        code_rtmr2=zero.hex(),
        body_kwargs={name: zero for name in ("rtmr0", "rtmr1", "rtmr2", "rtmr3")},
    )
    OUTPUT.write_text(json.dumps({"input": inputs}, indent=2) + "\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Regenerate the PQB vault script template, its slot layout and fixtures from pqb.

    python3 tools/pqb_template.py ~/ws/pqb          # needs coincurve, as pqb does

A PQB locking script (pqb construction `v1`) is a bare legacy scriptPubKey whose
only seed-dependent content is the 154 commitments of the BIP's root `R`, each a
20-byte push at a fixed position. This builds scripts with pqb for several
seeds, finds every commitment, checks that

- each sits behind a 0x14 push opcode, exactly once, at the same offset for every seed;
- nothing else differs between seeds;
- the script has no OP_CODESEPARATOR (so the co-signature's scriptCode is the whole script),

and that the slots form the arithmetic runs `LAYOUT` describes. It then writes

- `pqb-core/src/template.bin`: the script with every commitment zeroed;
- `tests/fixtures/pqb-script-seed0123.hex`: pqb's script for the BIP's test seed 00 01 .. 1f;

and prints the layout and script length that `pqb-core/src/template.rs`,
`tests/application_client/pqb.py` and `clients/js/src/pqb.ts` must carry. It
fails if they don't match.
"""
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def runs(slots):
    """Group (offset, root index) in script order into (push, stride, count, first) runs."""
    out = []
    for at, i in slots:
        if out:
            push, stride, count, first = out[-1]
            if count == 1:
                stride = at - (push + 1)
            if first + count == i and at == push + 1 + stride * count:
                out[-1] = (push, stride, count + 1, first)
                continue
        out.append((at - 1, 0, 1, i))
    return out


def main(pqb_repo):
    sys.path.insert(0, str(Path(pqb_repo) / "pqb" / "src"))
    from pqb.configs import get
    from pqb.lock import Lock
    from pqb._research.l1gen import parse_script
    sys.path.insert(0, str(ROOT / "tests"))
    from application_client import pqb as ref

    cfg = get()
    print("pqb construction", cfg.tag, cfg.version)
    seeds = [bytes(range(32)), bytes([7]) * 32, bytes([0xAA]) * 32]
    scripts = [Lock.build(cfg, s).script for s in seeds]
    length = len(scripts[0])
    layout = None
    template = None
    for seed, script in zip(seeds, scripts):
        assert len(script) == length
        assert not any(op == 0xAB for _, op, _, _ in parse_script(script)), "OP_CODESEPARATOR"
        cs = ref.commitments(seed)
        found = []
        for i, c in enumerate(cs):
            at = script.find(c)
            assert at > 0 and script.count(c) == 1 and script[at - 1] == 0x14, (i, at)
            found.append((at, i))
        found.sort()
        lay = runs(found)
        assert layout is None or lay == layout, "slot layout differs between seeds"
        layout = lay
        t = bytearray(script)
        for at, _ in found:
            t[at:at + 20] = bytes(20)
        assert template is None or bytes(t) == template, "the fixed bytes differ between seeds"
        template = bytes(t)
    assert sum(c for _, _, c, _ in layout) == 154

    print("SCRIPT_LEN =", length)
    print("LAYOUT =", layout)
    print("template sha256", hashlib.sha256(template).hexdigest())

    # The layout the code carries must be this one.
    rs = (ROOT / "pqb-core" / "src" / "template.rs").read_text()
    m = re.search(r"const LAYOUT: \[\(usize, usize, usize, usize\); \d+\] = \[(.*?)\];", rs, re.S)
    code = [tuple(int(x) for x in t) for t in re.findall(r"\((\d+), (\d+), (\d+), (\d+)\)", m.group(1))]
    assert code == layout, "update LAYOUT in pqb-core/src/template.rs: %r" % (code,)
    assert ("pub const SCRIPT_LEN: usize = %d;" % length) in rs, "update SCRIPT_LEN in template.rs"
    assert ref.LAYOUT == layout and ref.SCRIPT_LEN == length, "update tests/application_client/pqb.py"

    (ROOT / "pqb-core" / "src" / "template.bin").write_bytes(template)
    for seed, script in zip(seeds, scripts):
        assert ref.script(seed) == script
    fixtures = ROOT / "tests" / "fixtures"
    fixtures.mkdir(exist_ok=True)
    (fixtures / "pqb-script-seed0123.hex").write_text(scripts[0].hex() + "\n")
    print("ok: template.bin and fixtures written")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(Path.home() / "ws" / "pqb"))

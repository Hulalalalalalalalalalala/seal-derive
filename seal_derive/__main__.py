"""Command line entry point: ``python3 -m seal_derive --root <dir> <subcommand>``.

Exit codes: 0 success, 1 a storage or verification error, 2 a usage error.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import DOMAIN, SOURCE_CATEGORIES, __version__
from .core import KeyRing, SealError

USAGE_ERROR = 2

def _tags() -> list[str]:
    """Tags this domain claims: the comma-separated line that follows each named category heading."""
    import pathlib
    corpus = pathlib.Path(__file__).resolve().parent.parent / "corpus.md"
    if not corpus.is_file():
        return []
    wanted, tags, collect = set(SOURCE_CATEGORIES), [], False
    for line in corpus.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped in wanted:
            collect = True
            continue
        if not collect or not stripped:
            continue
        for token in stripped.split(","):
            token = token.strip().replace("\\", "")
            if token and token not in tags:
                tags.append(token)
        collect = False
    return tags


def _report(component_names: list[str], readiness: dict[str, bool]) -> str:
    import json
    return json.dumps({"domain": DOMAIN, "version": __version__, "sourceCategories": list(SOURCE_CATEGORIES),
                       "tags": _tags(), "components": component_names, "readiness": readiness},
                      ensure_ascii=False, sort_keys=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="seal_derive", description="口令派生与版本化封存")
    parser.add_argument("--root", required=True, help="working directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty store")
    for verb, help_text in (("load", "load material"), ("versions", "list versions"), ("active", "print the active version")):
        node = sub.add_parser(verb, help=help_text); node.add_argument("key_id"); node.add_argument("--password"); node.add_argument("--version", type=int)
    seal = sub.add_parser("seal", help="seal material under a key id")
    seal.add_argument("key_id"); seal.add_argument("material"); seal.add_argument("--password"); seal.add_argument("--iterations", type=int, default=200_000)
    for verb in ("set-active", "revoke"):
        node = sub.add_parser(verb); node.add_argument("key_id"); node.add_argument("version", type=int)
    sub.add_parser("report", help="print this domain's report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    ring = KeyRing(args.root)
    try:
        if args.command == "init":
            ring.init(); print(f"initialised {ring.path}")
        elif args.command == "seal":
            print(ring.seal(args.key_id, args.material, args.password, args.iterations))
        elif args.command == "load":
            sys.stdout.buffer.write(ring.load(args.key_id, args.version, args.password) + b"\n")
        elif args.command == "versions":
            print(json.dumps(ring.versions(args.key_id)))
        elif args.command == "active":
            print(ring.active(args.key_id))
        elif args.command == "set-active":
            ring.set_active(args.key_id, args.version); print("ok")
        elif args.command == "revoke":
            ring.revoke(args.key_id, args.version); print("ok")
        elif args.command == "report":
            print(_report(["keyring", "derive"], {"seal": True, "rotate": True, "revoke": True, "constantTime": False}))
        return 0
    except FileNotFoundError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except SealError as error:
        # Missing/mismatched passphrase, tampering, and legacy derived-only
        # records are verification failures, not usage mistakes.
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (KeyError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return USAGE_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

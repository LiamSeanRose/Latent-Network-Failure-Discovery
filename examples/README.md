# Example corpus

`two-site/` is the worked example [docs/TUTORIAL.md](../docs/TUTORIAL.md) walks through: six
devices across two sites, with four deliberate defects and a couple of things the tool has an
opinion about that are not defects at all.

Every file here is invented. No configuration, address plan, hostname or topology from any real
network is in this repository, and none may be added (docs/CONVENTIONS.md §4). The addresses are
RFC 1918, the AS numbers are from the 16-bit private range, and the device names describe roles
rather than anything that exists.

`tests/test_examples.py` asserts that this corpus still produces the findings the tutorial
claims, by rule id and device. If a rule changes and the tutorial goes stale, that test is what
says so.

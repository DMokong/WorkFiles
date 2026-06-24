"""Container-runtime helpers for the redteam harness.

Most of this directory is non-Python infrastructure (Dockerfile, compose,
entrypoint, otel config). `render_netpolicy` is the one piece of runtime logic
that is pure enough to live in, and be tested as, Python: the entrypoint shells
out to it to turn the engagement's egress allow-list into an nftables ruleset.
"""

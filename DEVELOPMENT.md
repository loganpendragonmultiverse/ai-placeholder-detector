# Development handoff

The scanner is intentionally deterministic. It does not label code as AI-generated, infer intent, or execute project code. Detection rules require a specific user-facing risk, realistic positive and negative fixtures, and an explanation that helps a maintainer decide what to do.

Scan completeness is a public contract: do not silently drop read failures or infer
resolved findings from incomplete inspection. `scan_report` preserves content-free
reasons while `scan` retains its findings-only compatibility shape. Traversal never
follows symlinks and prunes intentionally ignored directories.

Release from the exact reviewed, protected-main merge using an annotated version
tag. The tag workflow builds wheel and source distributions after tests; publish
those exact artifacts and verify installed acceptance and public hashes. Keep all
existing CI and default-setup CodeQL requirements.

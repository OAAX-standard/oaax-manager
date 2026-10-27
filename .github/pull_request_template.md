## What and why

<!-- One change per PR. Link the issue or steering-committee decision if there is one. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`)
- [ ] `uv run pytest` passes (add a test for a bug fix or a new behaviour)
- [ ] `src/oaax_manager/index.json` regenerated with `tools/gen_index.py` (if the artifacts in the store changed)
- [ ] `CHANGELOG.md` updated (if users notice the change)

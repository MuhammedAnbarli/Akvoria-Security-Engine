# Contributing

## Ground rules

1. **Defensive only.** No offensive capability, network scanning, exploitation,
   credential collection, stealth or automatic destruction. See
   [`SECURITY.md`](SECURITY.md).
2. **Truthful reporting.** A component must report the state it can verify. If a
   capability is unavailable, report it as unsupported — never silently degrade
   and never claim protection that is not implemented.
3. **No silent data loss.** Never delete or modify user files without explicit
   operator authorization.
4. **Tests come with the change.** New behavior needs a test that fails without
   the change.

## Development setup

```bash
git clone <repository-url>
cd akvoria-ase
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements-optional.txt   # optional
```

## Before opening a pull request

```bash
python3 -m compileall -q core modules main.py tests
python3 -m unittest discover -s tests -t . 
```

Both must pass. Do not delete or skip tests to make a run green — fix the code
or explain precisely why a test is wrong.

## Code style

- Standard library only for mandatory paths. Optional packages must degrade
  gracefully when absent.
- Imports at the top of the file.
- Comments only where the code expresses something genuinely non-obvious.
- Raise the `ASE*Error` types from `core/exceptions.py` rather than bare
  `Exception`.
- Never log secrets, tokens, key material or full file contents.

## Adding a module

A module is any object with `start()` and `stop()`. Register it in
`ASEEngine._register_modules()` and declare dependencies explicitly:

```python
self.module_manager.register("my_module", self.my_module,
                             dependencies=("intelligence",))
```

Return `False` from `start()` when the module is idle (for example, no
directories configured). The manager reports `idle`, not `running`.

## Adding an API endpoint

1. Add the route in `core/api.py`.
2. Authenticate through the existing `_gate()` or `authorize()` helpers — never
   bypass them.
3. Validate every input; reject non-object JSON.
4. Raise the specific `ASE*Error` type so the handler maps it to the right status.
5. Add a test in `tests/test_api_integration.py`.

## Commit messages

Use the imperative mood and explain *why*:

```
Reject symlinked database paths

Opening a symlinked database lets a local attacker redirect writes to an
arbitrary file. Refuse the path instead of resolving it.
```

## Reporting bugs

Include the ASE version (`python3 main.py --version`), the platform, the exact
command, and the relevant output of `python3 main.py diagnostics`.

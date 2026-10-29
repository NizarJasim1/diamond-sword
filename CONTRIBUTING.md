# Contributing

Issues and pull requests are welcome.

## Setup

```bash
git clone https://github.com/NizarJasim1/diamond-sword.git && cd diamond-sword
pip install ruff mypy
bash scripts/verify.sh       # compile, unit tests, mutation testing, ruff, mypy --strict
```

## Ground rules

1. **Every request goes through the transport chokepoint.** No module sends traffic
   on its own. Scope and rules of engagement are checked first and fail closed.
2. **No AI in the run path.** Crawling, interaction and capture stay deterministic.
3. **Humans own logins and destructive actions.** Don't add code that automates MFA
   or bypasses the consent gate.
4. **Core modules keep their mutation specs passing.** If you change `legal`,
   `coverage`, `heal`, `capture` or `pipeline`, run `scripts/verify.sh` and add
   mutants for new logic in `tests/mutants/`.
5. **Standard library only** in the core. Playwright and mitmproxy stay behind adapters.

## License of contributions

Diamond Sword is released under the PolyForm Noncommercial License 1.0.0 and is also
offered under separate commercial licenses. By opening a pull request you agree that
your contribution is licensed under the same terms and may be included in commercially
licensed versions of Diamond Sword.

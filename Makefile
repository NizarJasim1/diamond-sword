.PHONY: test verify lint typecheck clean

test:        ## unit tests (stdlib only)
	python3 -m unittest discover -s tests -t . -q

verify:      ## compile + tests + mutation specs + static gates
	bash scripts/verify.sh

lint:        ## ruff
	ruff check diamond_sword tests

typecheck:   ## mypy --strict
	mypy

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .mypy_cache .ruff_cache

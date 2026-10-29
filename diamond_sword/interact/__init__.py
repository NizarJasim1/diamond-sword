"""Interaction/exploration engine: drive a real browser, exercise every control, capture all
traffic as multi-principal HAR \u2014 deterministically and under a playbook written offline (by the operator, optionally with an LLM assistant).

This is the layer that turns Diamond Sword from a link-crawler into an action-crawler, so a logged-in
SPA is exercised the way a human would, with zero AI at runtime and every action
gated by ROE + consent."""

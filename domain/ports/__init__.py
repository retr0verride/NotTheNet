"""Domain ports (interfaces) — abstract contracts that infrastructure must satisfy.

Every protocol here is a PEP 544 structural subtype check.  Infrastructure
adapters are never imported here; they fulfil these contracts by duck-typing.
"""

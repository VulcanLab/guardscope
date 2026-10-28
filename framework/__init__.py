"""guardscope framework core (M1 pass 2).

Everything in this package defines or interprets measurement (DESIGN.md §2
"core science" layer): record schemas and constructors, the plugin
contracts, the experiment-file loader and validator, and the C1-C4
reconciliation library. No module here may behave differently depending on a
plugin's identity.
"""

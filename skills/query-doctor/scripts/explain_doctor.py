#!/usr/bin/env python3
"""Query Doctor — EXPLAIN plan runner and analyzer."""


def main() -> None:
    # TODO: connect to target DB, run EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON),
    # parse plan tree, flag seq scans on large tables, bad estimates, spills.
    pass


if __name__ == "__main__":
    main()

#!/bin/bash
cd "$(dirname "$0")/.."
echo "Running Argus V2 tests..."
python -m pytest tests/ -v --tb=short 2>&1 || python tests/test_models.py && python tests/test_database.py && python tests/test_patterns.py

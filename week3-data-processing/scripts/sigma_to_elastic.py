#!/usr/bin/env python3
"""Convert the Week 3 Sigma rule into an Elastic (Lucene) query using pySigma.

    pip install pysigma pysigma-backend-elasticsearch
    python3 scripts/sigma_to_elastic.py
"""
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend

rule = Path(__file__).resolve().parent.parent / "sigma" / "wannacry_recovery_inhibition.yml"
for q in LuceneBackend().convert(SigmaCollection.from_yaml(rule.read_text())):
    print(q)

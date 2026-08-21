"""Evaluation half of the project: prompt sets, detectors, and stored runs.

Kept separate from detection/ on purpose. detection/ defends the request
path; this package measures how well it does so. Merging them would let the
defense grade its own work -- see evaluation/detectors/base.py.
"""

# HACKATHON.md

## Event
Hacktoberfest 2026 | Hack Day Sonipat, Newton School of Technology, Rishihood University
Date: 31 October 2026

## Team
**Team name:** HardCarry

**Members:**
1. Aryansh Agarwal (Team Leader)
2. Atharv Gupta

## Selected Problem Statement
**Problem 04: Published Package vs Source Code Integrity Analyzer**
Category: Software Supply Chain Security | Package Management | Security Automation

We are building a tool that retrieves a published npm or PyPI package, finds its matching source repository and tag, compares the two, explains why each difference exists, and flags suspicious modifications with an evidence-backed risk assessment. It also monitors new releases of selected packages.

## AI Models Used
| Model | Runtime | Size | Role in the project |
|---|---|---|---|
| beam (`beam:cloud`) | Ollama cloud | 501.3B total parameters, 23.4B active (mixture-of-experts) | Explains individual source-vs-package differences and assists in classifying them as benign build output or suspicious |

## Why We Chose This Model
- It is an open-weight model served through Ollama, and its large total parameter count gives stronger reasoning over code diffs than the small models that fit on a laptop.
- Only 23.4B parameters are active per token, so responses stay fast enough for interactive use and for monitoring many releases.
- Inference runs on Ollama's cloud rather than on our laptops. Only the specific diff snippets sent for explanation are shared with the model, never whole packages.
- Deterministic checks (file hashing, diffing, provenance and attestation verification) make the primary decisions. The model is used for explanation and ambiguous cases, and every verdict links back to concrete evidence.

## Tech Stack
Python, with model inference through the Ollama API.

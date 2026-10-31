"""Benchmark metrics helpers."""

from __future__ import annotations


def compute(results):
    tp = sum(1 for r in results if r.label == "malicious" and r.predicted_malicious and not r.inconclusive)
    tn = sum(1 for r in results if r.label == "benign" and (not r.predicted_malicious) and not r.inconclusive)
    fp = sum(1 for r in results if r.label == "benign" and r.predicted_malicious and not r.inconclusive)
    fn = sum(1 for r in results if r.label == "malicious" and (not r.predicted_malicious) and not r.inconclusive)
    inc = sum(1 for r in results if r.inconclusive)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    denom = (tp + tn + fp + fn)
    accuracy = (tp + tn) / denom if denom else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return tp, tn, fp, fn, inc, precision, recall, specificity, f1, accuracy, fpr, fnr

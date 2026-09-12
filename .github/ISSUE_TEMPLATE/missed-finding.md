---
name: Missed finding
about: Something dangerous that the scanner walked past
title: "Missed: <what it should have found>"
labels: missed-finding
---

**What it should have found**
<!-- The shape, not the secret. Never paste a live credential into an issue;
     replace the middle with asterisks the way the scanner would. -->

**The file it was in** <!-- format and, if it matters, why the format is
     unusual: a Helm template, a JSON CloudFormation stack, an unusual
     indentation style -->

**Which rule you expected**
<!-- `repo-sentinel rules` lists them. "None of them, this needs a new one" is
     a fine answer. -->

**Is it a documented shape?**
<!-- A vendor-documented prefix means a high-confidence rule is possible. If it
     is only recognisable by entropy, say so -- that changes what the rule can
     honestly claim. -->

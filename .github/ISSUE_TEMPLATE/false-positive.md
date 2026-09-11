---
name: False positive
about: The scanner reported something that is not a problem
title: "False positive: RULE on <what it was>"
labels: false-positive
---

<!-- This is the most useful issue you can open. Every false-positive class
     fixed so far came from a real file somebody pointed at. -->

**Rule:** <!-- e.g. SEC100 -->

**What the value actually was**
<!-- "a YAML anchor", "the name of an environment variable", "a Kubernetes
     label selector". This is the part that matters: the fix is usually a rule
     about that category of thing, not about this one line. -->

**The line, redacted if it needs it**
```
paste here
```

**Where it lives** <!-- path and file type; whether it is source, a fixture,
     documentation, generated -->

**Anything that would help tell it apart from a real finding**
<!-- If you cannot think of anything, say so. "This is indistinguishable from
     a real credential" is a valid and useful answer -- it usually means the
     right fix is a suppression marker rather than a rule change. -->

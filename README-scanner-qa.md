# Owned scanner QA branch

Owned synthetic STATIC inputs for Matgatz/vornin-immediate-qa. Never install packages, execute app.js/render.js, deploy the Kubernetes YAML, or add CI/workflow/package scripts.

This branch controls exactly CVE-2021-23337 in lodash, Kubernetes KSV-0017 Privileged, and vornin-javascript-insecure-innerhtml. The synthetic npm parent is graph metadata, not a downloadable package. Other advisories may remain in lodash4.17.21. Compliant means fixed for these three detectors only.

# Maintainer rules

Keep code and PowerShell readable with four-space indentation and expanded
control flow. Public commands stay at the root; internal helpers in powershell/
with platform/architecture and all fallbacks where needed.

Distribute this mini-tool only as Windows ZIP / Linux tar.gz. Do not add MSI/DEB
packaging, global PATH updates, services or automatic production activation.
Never print keys/passwords or commit user data. Require explicit operator approval
for changes to a live BBS. Document actual supported formats and native tests.

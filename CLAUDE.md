# QuodVPN — Claude Code Guidelines

## Version Bump Requirement

**Every commit that modifies `Connect-QuodVPN.ps1` must also:**

1. Increment `$SCRIPT_VERSION` (e.g. `"5.32"` → `"5.33"`) at line ~92
2. Update `$VERSION_DATE` to today's date in `DDMONYY` format (e.g. `"24MAR26"`) at line ~93
3. Replace the `$script:VERSION_NOTES` block (line ~101) with a bullet-point summary of the changes in that commit

This applies to all changes regardless of size — a one-line fix still requires a version bump.

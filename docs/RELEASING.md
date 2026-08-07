# Releasing autostream

This guide covers the steps for publishing stable and dev (pre-release) releases of autostream and autostream-dial.

---

## Supported tag formats

```
vMAJOR.MINOR.PATCH
vMAJOR.MINOR.PATCH-alpha.N
vMAJOR.MINOR.PATCH-beta.N
vMAJOR.MINOR.PATCH-rc.N
```

Ordering: `alpha.N < beta.N < rc.N < final` within any given `vMAJOR.MINOR.PATCH`. Numeric ordering applies within each label: `beta.2 < beta.10`.

---

## Stable release

1. Tag the commit: `git tag vMAJOR.MINOR.PATCH`
2. Push the tag: `git push origin vMAJOR.MINOR.PATCH`
3. On GitHub, create a new **Release** from the tag.
4. Leave **Set as a pre-release** unchecked.
5. Publish.

Both stable-channel and dev-channel appliances may receive the new release — it is the newest at `/releases/latest` and the newest non-draft at `/releases?per_page=1`.

---

## Dev (pre-release) release

1. Tag the commit: `git tag vMAJOR.MINOR.PATCH-beta.N` (or `-alpha.N` / `-rc.N`)
2. Push the tag: `git push origin vMAJOR.MINOR.PATCH-beta.N`
3. On GitHub, create a new **Release** from the tag.
4. Check **Set as a pre-release**.
5. Publish.

Only dev-channel appliances see this release. Stable-channel appliances query `/releases/latest`, which GitHub only returns for non-pre-release releases.

---

## Promoting a pre-release to stable

Publish a new GitHub Release for the final `vMAJOR.MINOR.PATCH` tag (without the pre-release suffix), leaving **Set as a pre-release** unchecked. Do not edit the existing pre-release — create a new Release.

---

## Draft releases

Draft releases are not returned by the GitHub releases API to unauthenticated callers and are invisible to all appliance channels. No special filtering is required.

---

## Pi appliance verification

The checks below are for maintainers publishing a release. They need a running
test appliance and are not part of building or contributing to autostream — if
you are not publishing, you can stop here.

Before tagging a release, verify on a test appliance:

- Open `http://autostream.local/about`, tap **System**, and confirm the System Info card populates (build versions, CPU temperature, disk usage) and all six service rows show **OK** within a few seconds.
- Run `sudo systemctl stop vibra-mini.service`, reload the System page, and confirm the **Vibra Mini** row changes to **Failed**. Then `sudo systemctl start vibra-mini.service` and confirm it returns to **OK**.
- If any other service row shows **Failed** before the stop/start test, investigate the unit before releasing.

### Update path

Run one full in-app update, from the previous release to the release candidate, and confirm:

- The Web UI switches to the **updating** holding page as soon as the update starts, and stays reachable throughout.
- `owntone-mini` and `vibra-mini` are **skipped** in the update log when the pinned versions are unchanged from the previous release (`OwnTone Mini <version> already installed; skipping source rebuild`). If the release bumps a pin, confirm the rebuild instead runs and completes.
- The appliance reboots on its own at the end, comes back on the network, and the About → System card shows the new build versions.
- Audio output works after the reboot without any manual service start.

If the release changes the update path itself, also force a failure mid-update (for example by pointing `AUTOSTREAM_OWNTONE_MINI_REPO` at an unreachable source) and confirm the stopped services are restarted automatically and the appliance returns to a working state.

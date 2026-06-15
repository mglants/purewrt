# PureWRT package-feed signing keys

OpenWrt's two package formats use **different** signing schemes, so the feed needs **two keypairs**.
Generate them **once, offline**, keep the private keys safe (GitHub Actions secrets), and commit only the
**public** keys here — `release.yml` republishes them at the feed root so `install.sh` can fetch them.

## opkg / `.ipk` (OpenWrt 24.10 and earlier) — usign (Ed25519)

The feed's `Packages` index is signed (`Packages.sig`) with OpenWrt's `usign` tool (signify-compatible).

```sh
# needs `usign` (apt: signify-openbsd provides a compatible tool, or build from
# https://git.openwrt.org/project/usign.git)
usign -G -s purewrt-usign.sec -p purewrt-usign.pub -c "PureWRT feed"
```

- Commit `purewrt-usign.pub` here.
- Put the **secret** key's contents into the GitHub secret `USIGN_SECRET_KEY`
  (`base64 -w0 purewrt-usign.sec` is fine — `feed:index` base64-decodes if it can, else uses raw).
- Clients trust it with `opkg-key add purewrt-usign.pub` (install.sh does this).

## apk / `.apk` (OpenWrt 25.12+, apk v3) — RSA

The `packages.adb` index is signed with an RSA key.

```sh
openssl genrsa -out purewrt-apk.rsa 2048
openssl rsa -in purewrt-apk.rsa -pubout -out purewrt-apk.rsa.pub
```

- Commit `purewrt-apk.rsa.pub` here.
- Put the **private** key into the GitHub secret `APK_PRIVATE_KEY` (`base64 -w0 purewrt-apk.rsa`).
- Clients trust it by dropping the public PEM into `/etc/apk/keys/` (install.sh does this); if name-based
  verification is awkward on apk v3, install.sh falls back to `apk add --allow-untrusted -X <index>`.

## Summary

| Secret (private)      | Committed (public)       | Format | Signs            |
|-----------------------|--------------------------|--------|------------------|
| `USIGN_SECRET_KEY`    | `purewrt-usign.pub`      | opkg   | `Packages.sig`   |
| `APK_PRIVATE_KEY`     | `purewrt-apk.rsa.pub`    | apk    | `packages.adb`   |

Never commit the secret keys. Rotating a key means re-publishing the new public key and having clients
re-run `install.sh`/`feed.sh`.

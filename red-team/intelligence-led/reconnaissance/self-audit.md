# Personal Digital-Footprint Self-Audit

The security companion to the footprint-reduction report. Every step here is
something **you run against your own accounts and identifiers** — this is a
self-audit, not reconnaissance on anyone. Each check names the fix and the
ATT&CK technique (and this repo's detection ID) it shuts down, so reducing your
footprint maps directly to the attacks the framework emulates.

> Run the whole thing once, fix what it surfaces, then re-run on the cadence at
> the bottom. Nothing here collects data on other people.

---

## Priority ladder (if you do nothing else, do these)

1. **Breach + reused passwords** → unique passwords + a manager
2. **MFA everywhere that matters** → phishing-resistant where possible
3. **Revoke stale OAuth grants** → kills silent mailbox access
4. **Carrier port-out/SIM PIN** → defeats SIM-swap account takeover
5. **Rotate any leaked secret in your repos** → before bots use it

Everything below expands on these and adds the long tail.

---

## 1. Breach & credential exposure  ·  counters: T1078 Valid Accounts, T1110 Brute Force

| Check | How | Fix |
|-------|-----|-----|
| Email in breaches | `haveibeenpwned.com` for every address | Change the password *everywhere it was reused*; the reuse is the risk |
| Password in cracking corpora | `haveibeenpwned.com/Passwords` (k-anonymity — password never leaves your browser) | Treat any hit as burned; replace it |
| Ongoing monitoring | Register your emails for HIBP notifications | Turns a one-time check into an alert stream |
| Password hygiene | Password manager's built-in audit (reused / weak / old) | Unique password per site; rotate the weak/reused ones |

**Level up:** move high-value accounts to **passkeys / hardware keys** where
offered — phishing-resistant, nothing to reuse or breach.

## 2. Secrets in your own code  ·  counters: T1552.001 Credentials In Files (see also the repo's secret-scan workflow)

| Check | How | Fix |
|-------|-----|-----|
| Live secret leaks | GitHub → Settings → Code security → **Secret scanning alerts** | **Rotate first** (revoke+reissue), then scrub history with `git filter-repo` |
| Historical leaks | Run `gitleaks detect` / `trufflehog` on your own repos locally | Same: rotate, then remove |
| Prevention | Enable **push protection**; add a pre-commit secret hook | Stops the next leak at commit time |

Removing a secret without rotating is useless — assume it was scraped within
minutes of being public.

## 3. Search-engine & data-broker footprint  ·  counters: T1589 Gather Identity Info, pretext-building

| Check | How | Fix |
|-------|-----|-----|
| Name results | Search `"your name"`, `name + city`, `name + employer` | Separate *you published this* from *a broker aggregated it* |
| Google exposure | Google account → **Results about you** | Request removal of pages leaking contact info/address; enable alerts |
| People-search sites | Spokeo, WhitePages, BeenVerified, Radaris, Intelius, TruePeopleSearch | Opt out on each (they re-list — recheck), or automate with DeleteMe/Kanary |
| Reverse image | Search your profile photo | Find accounts/impersonations reusing it |

## 4. Social media exposure  ·  counters: T1593.001 Social Media recon, pretexting

| Check | How | Fix |
|-------|-----|-----|
| Privacy settings | Each platform's privacy checkup | Lock down audience; hide friend/connection lists (used for pretext) |
| Old content | Review years-back posts for PII, locations, employer detail | Delete/lock; strip geotags |
| Photo geotags | Check whether posts embed GPS | Turn off location on the camera/app |
| Oversharing signals | Job title + tech stack + schedule = spear-phish fuel | Trim specifics; assume recruiters aren't the only readers |
| Impersonation | Search for accounts using your name/photo | Report duplicates |

## 5. Phone number & SIM  ·  counters: T1621 MFA request abuse / SIM-swap (Scattered Spider → H-03, C-01)

| Check | How | Fix |
|-------|-----|-----|
| Port-out protection | Ask your carrier for a **port-freeze / transfer PIN** | Enable it — this is the #1 SIM-swap defense |
| Number in breaches | HIBP also indexes phone numbers | If exposed, expect smishing; be strict about SMS codes |
| SMS as MFA | Inventory accounts using SMS 2FA | Move to an authenticator app / passkey; SMS is the weakest factor |
| Voicemail PIN | Set a non-default PIN | Blocks voicemail-based reset tricks |

## 6. Email security posture  ·  counters: BEC / mailbox persistence (T1114, inbox rules → C-03)

| Check | How | Fix |
|-------|-----|-----|
| Forwarding & rules | Check auto-forward + all inbox rules on every mailbox | Delete anything you didn't create — hidden rules are classic account-takeover persistence |
| Aliases | Audit what addresses reach you | Use per-service aliases/plus-addressing to trace leaks |
| Recovery address | Confirm the recovery email is one you control + secured | A compromised recovery email unravels everything |
| App passwords | Revoke legacy "app passwords" that bypass MFA | Modern OAuth instead |

## 7. Account & device review  ·  counters: T1528 OAuth token theft (APT29 → H-01), session hijack

| Check | How | Fix |
|-------|-----|-----|
| Login history | Google/Microsoft/Apple "recent security activity" | Sign out unknown sessions; change password if surprised |
| Active devices | Review registered devices | Remove ones you no longer own |
| **OAuth / app grants** | Review third-party apps connected to each account | **Revoke anything unused**, especially with mail/file scope — this is APT29's move |
| MFA device list | Confirm only *your* MFA devices are registered | Remove unknown ones (attacker-registered MFA = persistence, H-04) |

## 8. Financial & identity monitoring  ·  counters: downstream fraud from any of the above

| Check | How | Fix |
|-------|-----|-----|
| Credit freeze | Freeze at all bureaus (free) | Blocks new-account fraud; thaw on demand |
| Statement review | Scan for small "test" charges | Dispute early |
| Identity monitoring | Bank/card issuer alerts, or a monitoring service | Real-time notice of misuse |
| Tax/gov accounts | Set an IRS IP-PIN / equivalent where available | Blocks refund fraud |

## 9. Metadata & document leakage  ·  counters: T1592 host/identity info from files you share

| Check | How | Fix |
|-------|-----|-----|
| Photo EXIF | Inspect a photo you posted for GPS/device metadata | Strip metadata before sharing |
| Document authorship | Check Office/PDF properties (author, org, path) | Clear document metadata before publishing |
| Resume/CV | Look for home address, full DOB, personal email | Minimize PII; use a contact form |

## 10. Home network & devices  ·  counters: exposed-service recon (your own perimeter)

| Check | How | Fix |
|-------|-----|-----|
| Router admin | Log in; is it a default password? Firmware current? | Change creds; update firmware; disable remote admin/UPnP |
| Your public IP | From your own network, check what's exposed (your ISP/router tools) | Close/forward-off anything unexpected |
| IoT defaults | Inventory smart devices | Change default creds; segment onto a guest VLAN |
| Wi-Fi | WPA3/WPA2, strong passphrase, guest network for visitors/IoT | Rotate a weak passphrase |

## 11. Browser & endpoint hygiene  ·  counters: token/session theft, malicious extensions

| Check | How | Fix |
|-------|-----|-----|
| Extensions | Audit installed browser extensions + their permissions | Remove ones you don't use / that over-ask |
| Saved passwords | Review browser-stored creds | Migrate to a real password manager |
| OS & app updates | Confirm auto-update is on | Patch — most real intrusions use known, fixed bugs |
| Disk encryption + screen lock | FileVault/BitLocker on; short auto-lock | Hardens a lost/stolen device |

## 12. Recovery-path hardening  ·  counters: help-desk / recovery social engineering (Scattered Spider)

| Check | How | Fix |
|-------|-----|-----|
| Backup codes | Generate and store MFA backup codes offline | Prevents lockout *and* reduces reliance on SMS reset |
| Recovery questions | Replace guessable answers | Use random answers stored in your manager |
| Carrier/ISP account PIN | Set account-level PINs | Blocks phone-based pretext resets — the exact Scattered Spider vector |

---

## Cadence

| When | Do |
|------|-----|
| **Now (once)** | The full pass above; fix P1–P5 immediately |
| **Continuous** | HIBP alerts, Google Results-about-you alerts, bank/credit alerts |
| **Monthly** | Statement review; skim login history on primary accounts |
| **Quarterly** | Re-run OAuth-grant review, inbox-rule check, broker opt-out recheck, extension audit |
| **Annually** | Full re-run; rotate high-value passwords; review recovery paths |

## What "good" looks like

- No reused passwords; unique + managed; passkeys on the crown-jewel accounts
- MFA (app/hardware, not SMS) on email, financial, and primary identity accounts
- Carrier port-freeze/PIN set; SMS demoted as a factor
- Zero live secrets in public repos; push protection on
- Brokers opted-out with monitoring; minimal public PII
- No unrecognized OAuth grants, inbox rules, MFA devices, or sessions
- Credit frozen; alerts on; recovery paths hardened
- (If you own a domain) DMARC enforcing; no internal names in public certs

---

**How this maps back to the framework:** the exposures you close here are the
*inputs* to the reconnaissance phase (`attack-surface.json`) and the *entry
points* for the actors in `threat-actors.json`. Shrinking your footprint is the
one control that beats passive OSINT — because passive recon is undetectable, so
the only defense is having less to find.

**Last Updated**: 2026-08-24

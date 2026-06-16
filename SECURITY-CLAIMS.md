# Security Claims — Pre-Draft (Phase 0 deliverable 0.5)

📄 **Governs:** CRYPTO-SPEC §7.1 (MVP residual), §12; THREAT-MODEL §12
(LINDDUN-Unawareness), §13 (R-1/R-3/R-4); ROADMAP Phase 0 item 0.5 + Phase 5 launch
checklist item #2.
**Status:** **PRE-DRAFT — not cleared for publication.** Two gates apply before any of
this copy goes public:
1. The **cryptographer's ruling** on whether MVP may use the words "zero-knowledge"
   pre-OPAQUE (REVIEW-PACKET §2, the judgment call). The wording below is written to
   the *honest MVP reality* and is conservative pending that ruling.
2. The **lawyer's ToS/privacy-policy accuracy review** (BLUEPRINT §10 Q3).

> **Why draft this now (before launch, before code):** the easiest way to ship a lie
> is to write marketing copy against the *ideal* design and forget the MVP ships with a
> caveat. Drafting the claims during Phase 0, matched to what the crypto actually does,
> means the reviewers can check honesty early and the launch checklist (Phase 5 #2)
> has something concrete to verify against.

---

## 1. What we may claim (true in MVP, native model)

These hold under the spec as written and the native delivery model:

- **"Your data is encrypted on your device. We can't read it."** The server stores
  ciphertext, a login verifier, and non-sensitive metadata — never your name, email,
  breaches, broker matches, or letter contents. (CRYPTO-SPEC §2, §4.3, §5.)
- **"Encrypted under a key only you hold."** Encryption keys are derived on your device
  from your password and never leave it. (CRYPTO-SPEC §3.3, §4.)
- **"A breach or subpoena of our servers reveals nothing readable about you."**
  (THREAT-MODEL §9 DA-1/DA-5.)
- **"One user can never read another's data"** — isolation is cryptographic, not just a
  permission check. (THREAT-MODEL P7.)
- **"We don't look people up. We only ever work on your own information, entered on
  your device."** (THREAT-MODEL DA-4.)

## 2. What we must NOT claim in MVP (overclaim register)

- ❌ **"Mathematically impossible for anyone, ever, to access your data."** False while
  R-1 (below) exists and while device compromise is out of scope.
- ❌ **"Even with unlimited resources we could never attack your account."** The MVP
  offline-dictionary path (R-1) makes this untrue for weak passwords until OPAQUE.
- ❌ **Unqualified "zero-knowledge"** — **pending the cryptographer's ruling.** If they
  rule MVP may use the term, it must carry the §3 caveat; if not, we say
  "end-to-end encrypted" and reserve "zero-knowledge" for the OPAQUE release.
- ❌ **"We monitor your footprint 24/7."** We check when you open the app / on an opt-in
  on-device schedule. True ZK can't scan while you're logged out. (CRYPTO-SPEC §12,
  BLUEPRINT §7.)
- ❌ **"Forgot your password? We'll help you back in."** We cannot — see §3.

## 3. Mandatory disclosures (must be visible, not buried)

These are honesty obligations (THREAT-MODEL §12, LINDDUN-Unawareness). Each maps to a
real residual the user is entitled to know about.

1. **Recovery = possible permanent data loss (R-3).** *"If you lose both your password
   and your recovery code, your data cannot be recovered — by anyone, including us.
   This is the cost of encryption only you can unlock."* Shown at signup and on the
   security screen.
2. **Password strength matters (R-1).** *"Your password is the lock on your data.
   Because only you hold the key, a weak password is the one realistic way it could be
   attacked — choose a strong, unique passphrase."* Pair with an enforced
   strong-passphrase policy (ROADMAP Phase 5 D5.7).
3. **What the server can see (R-4 / metadata).** *"We can see that your account exists,
   your subscription status, and when and roughly how much data you sync — never its
   contents."* Belongs in the privacy policy.
4. **Recovery code is password-equivalent.** *"Anyone with your recovery code can
   unlock your data. Store it like a password."* (CRYPTO-SPEC §3.4.)
5. **(If a web tier ever ships) weaker trust model.** Disclosed separately; out of v1.
   (BLUEPRINT §2.1.)

## 4. The OPAQUE delta (what changes when we upgrade)

When OPAQUE ships (post-v1, CRYPTO-SPEC §6.2), R-1 closes: the server can no longer
mount the offline dictionary attack even in principle. At that point the §2 ❌ on
unqualified "zero-knowledge" can be revisited with the cryptographer, and disclosure
#2's framing softens. **Until then, all copy tracks the MVP reality.** Do not pre-write
post-OPAQUE claims into MVP marketing.

## 5. Sign-off coupling

This pre-draft is finalized in **ROADMAP Phase 5 (launch checklist #2: "security copy
matches actual crypto state")**, conditioned on:
- [ ] Cryptographer's ZK-language ruling applied (§2/§3 reconciled to it).
- [ ] Lawyer's accuracy review of the final ToS/privacy-policy wording (BLUEPRINT §10 Q3).
- [ ] The crypto state at launch confirmed = MVP (not OPAQUE), so §4 has not silently
      been assumed.

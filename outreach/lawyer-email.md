# Lawyer — Reviewer Engagement Email (draft)

Outreach draft to engage counsel for the Phase 0 compliance review
(see [../BLUEPRINT.md](../BLUEPRINT.md) §10 and [../REVIEW-PACKET.md](../REVIEW-PACKET.md) §4).
The only remaining blank is `[name]` (the recipient) — fill it per send.

**Dependency note:** question 3 (ToS accuracy) partly hinges on the cryptographer's
ruling on whether MVP may use "zero-knowledge" language — have that ruling in hand, or
flag it to counsel, before finalizing privacy-policy wording.

---

**Subject:** Privacy/data-broker law — pre-launch review for a zero-knowledge consumer app (focused scope)

Hi [name],

I'm launching **vanish**, a privacy-first consumer app that helps an individual monitor and reduce their own digital footprint — breach exposure, data-broker presence, and removal-request tracking. It's built on a **zero-knowledge** architecture: user data is encrypted on the user's device and the server stores only ciphertext (no readable personal data, and we sell nothing). I'm looking for counsel with **US state privacy / data-broker / consumer-protection** experience to make a few specific determinations **before launch**.

This is a bounded, pre-launch engagement — I'm not after open-ended advice, but written answers to four questions that gate whether and how I can launch:

1. **Data-broker registration (CA / OR / TX / VT).** We help users file *their own* removals, store no readable personal data, and sell nothing — so I believe we're an agent *for* the consumer, not a data broker. **Does that hold per state, and does any registration obligation attach?**
2. **Breach-notification duties.** Our store is ciphertext with **no operator-held decryption key**. **Do encrypted-at-rest / no-key safe-harbor provisions exempt us from breach-notification in the target states, and under what conditions?**
3. **ToS / privacy-policy accuracy.** Our public security claims must match the actual cryptographic guarantees. **I need the claims reviewed for accuracy** (misstating the security model is itself exposure, e.g. FTC "deceptive practices"), plus confirmation of the disclosures we must make — notably the limited metadata the server *can* see, and that account recovery can mean **permanent data loss** by design.
4. **Authorized-agent line (this scopes v1).** In v1 the user sends their own removal letters — **the server never submits on a user's behalf.** Does this keep us clear of CCPA/GDPR **authorized-agent** obligations, and **specifically what would trip them** — i.e., what can I *not* add without crossing into agent territory?

I've prepared a short packet that frames these precisely: a **2-page brief (`REVIEW-PACKET.md`)** plus a design doc (`BLUEPRINT.md`) whose §10 lays out each question with context. **Out of scope** for this round: anything involving us submitting removals on users' behalf (a possible later feature I want to keep fenced until you weigh in), and the cryptographic implementation itself (separately reviewed).

**Deliverable:** a written memo answering the four questions, with any required ToS/privacy-policy language or conditions, suitable to rely on for launch.

A few logistics:
- Is this within your practice area, and **how would you scope / price it**? Glad to talk it through.
- What turnaround could you offer for the memo? No hard launch date locked on my end yet.
- Happy to send the packet under engagement/NDA at whatever point you prefer.

Thanks very much — I've tried to make the questions specific so they're efficient to answer. Glad to set up a short call.

Best,
Iceberg

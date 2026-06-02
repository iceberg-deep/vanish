"""Removal-request letter templates (CCPA / GDPR / generic).

These produce a letter asking a data broker to delete and suppress a record.
Identifiers (name, email, phone, address) are supplied at generation time and
used ONLY to render the letter — the caller is responsible for never persisting
them. When the request is filed by an authorized agent, the letter says so and
offers proof on request, as the CCPA/GDPR authorized-agent rules require.
"""

from datetime import date

TEMPLATES = ("ccpa", "gdpr", "generic")

AGENT_LINE = (
    "I am the designated authorized agent for the consumer named below, "
    "acting with their permission, and can provide proof of authorization "
    "on request."
)


def _contact_block(name, email, phone, address):
    lines = [name]
    if address:
        lines.append("Address: " + address)
    if email:
        lines.append("Email: " + email)
    if phone:
        lines.append("Phone: " + phone)
    return "\n".join(lines)


def _today():
    return date.today().isoformat()


def _agent_preamble(as_agent):
    """Returns the authorized-agent sentence (with trailing newlines) or ''."""
    return (AGENT_LINE + "\n\n") if as_agent else ""


def render(template, broker, name, email, phone=None, address=None,
           as_agent=False):
    """Return a removal-request letter as a plain string.

    `as_agent=True` prepends authorized-agent language. None of these arguments
    are stored anywhere by this function.
    """
    if template not in TEMPLATES:
        raise ValueError("unknown template: %s" % template)
    broker_name = broker["name"] if isinstance(broker, dict) else str(broker)
    contact = _contact_block(name, email, phone, address)
    agent = _agent_preamble(as_agent)

    if template == "ccpa":
        return _ccpa(broker_name, name, email, contact, agent)
    if template == "gdpr":
        return _gdpr(broker_name, name, email, contact, agent)
    return _generic(broker_name, name, email, contact, agent)


def _ccpa(broker_name, name, email, contact, agent):
    return """\
Date: {date}

To: Privacy / Compliance Team, {broker}

Subject: CCPA/CPRA Request to Delete and Opt Out of Sale of Personal Information

To Whom It May Concern,

{agent}I am submitting this request under the California Consumer Privacy Act
(Cal. Civ. Code 1798.100 et seq.), as amended by the CPRA, on behalf of the
consumer whose personal information is at issue.

I request that {broker}:

  1. DISCLOSE the specific pieces of personal information you have collected
     about this consumer, the sources, and the categories of third parties to
     whom it has been sold or shared.
  2. DELETE all personal information you have collected about this consumer.
  3. OPT OUT of any sale or sharing of this consumer's personal information.
  4. SUPPRESS the record so it does not reappear in future data sets.

Identifying information for verification:

{contact}

Please confirm completion in writing to {email}. Under the CCPA you must
respond within 45 days. Do not use the information in this request for any
purpose other than processing it.

Sincerely,
{name}
""".format(date=_today(), broker=broker_name, contact=contact,
           email=email or "(the contact email)", name=name, agent=agent)


def _gdpr(broker_name, name, email, contact, agent):
    return """\
Date: {date}

To: Data Protection Officer, {broker}

Subject: GDPR Request — Right to Erasure (Art. 17) and Access (Art. 15)

Dear Data Protection Officer,

{agent}Under the EU General Data Protection Regulation I am exercising the
following rights on behalf of the data subject identified below.

I request that {broker}:

  1. Confirm whether you process personal data concerning this data subject,
     and provide a copy together with the information required by Article 15.
  2. ERASE all personal data concerning them pursuant to Article 17 (right to
     be forgotten), including data shared with third parties.
  3. Cease any further processing and inform any recipients of the erasure as
     required by Article 19.

Identifying information for verification:

{contact}

Please respond within one month as required by Article 12(3), confirming the
action taken, to {email}. This request is made free of charge.

Yours faithfully,
{name}
""".format(date=_today(), broker=broker_name, contact=contact,
           email=email or "(the contact email)", name=name, agent=agent)


def _generic(broker_name, name, email, contact, agent):
    return """\
Date: {date}

To: Privacy Team, {broker}

Subject: Opt-Out and Record Removal Request

Hello,

{agent}I am writing to request the removal and suppression of the personal
listing described below from {broker} and any associated/affiliated sites.

Please:

  1. Remove the public listing(s) and delete the associated personal information.
  2. Opt this person out of any sale, sharing, or licensing of their data.
  3. Suppress the information so it does not reappear in future updates.

Information for matching and verification:

{contact}

Please confirm once this is complete by replying to {email}.

Thank you,
{name}
""".format(date=_today(), broker=broker_name, contact=contact,
           email=email or "(the contact email)", name=name, agent=agent)

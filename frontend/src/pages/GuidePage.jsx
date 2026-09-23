const TOPICS = [
  {
    icon: "▣",
    title: "How to spot a suspicious URL",
    body: [
      "Read URLs right-to-left: the domain that matters is just before the first single slash. In secure-paypal.com.login-verify.xyz/auth the real domain is login-verify.xyz — not paypal.",
      "Watch for hyphen-stuffed hosts, long random strings, and domains that imitate brands with extra words like 'secure', 'login', 'verify', or 'update'.",
    ],
  },
  {
    icon: "🔒",
    title: "Why HTTPS alone doesn't prove legitimacy",
    body: [
      "HTTPS encrypts traffic in transit; it says nothing about who owns the site. Any attacker can get a free TLS certificate in minutes.",
      "The padlock means the connection to whatever-host is encrypted — even if whatever-host is a phishing kit. Check the domain itself, not the lock.",
    ],
  },
  {
    icon: "◑",
    title: "Lookalike domains (typosquatting)",
    body: [
      "Attackers register domains one character away from the real thing: paypa1.com (digit 1), rnicrosoft.com (rn reads as m), app1e-id.com.",
      "Homoglyphs swap look-alike Unicode letters (Cyrillic 'а' inside a Latin word) — visually identical, technically a different domain.",
    ],
  },
  {
    icon: "⌗",
    title: "Suspicious subdomains",
    body: [
      "A brand name can appear anywhere in a subdomain: paypal.com.evil.xyz is owned by evil.xyz. Only the registrable domain (eTLD+1) identifies the site's true owner.",
      "Deep subdomain chains (4+ levels) are a common way to smuggle a trusted word into the address bar.",
    ],
  },
  {
    icon: "⬒",
    title: "IP-address URLs",
    body: [
      "Legitimate consumer sites virtually never serve content from a raw IP like http://23.22.14.105:8080/signin.",
      "IP hosts skip DNS entirely — no domain registration to trace — making them a staple of credential-harvesting kits.",
    ],
  },
  {
    icon: "↗",
    title: "URL shortener risks",
    body: [
      "Shorteners (bit.ly, t.co, cutt.ly…) hide the destination until you click. That opaqueness is exactly what phishers exploit in messages.",
      "Many shorteners offer preview endpoints; when in doubt, expand the link first or navigate to the company directly.",
    ],
  },
  {
    icon: "◐",
    title: "Unicode / IDN tricks",
    body: [
      "Internationalized domain names allow non-ASCII characters. Punycode hosts start with xn-- — sometimes legitimate, sometimes a homoglyph attack.",
      "Encoded characters (%xx) in odd places can hide the real path from a casual glance.",
    ],
  },
  {
    icon: "✉",
    title: "Credential-harvesting warning signs",
    body: [
      "Urgency and fear: 'your account will be suspended', 'verify within 24 hours', 'unusual sign-in detected'.",
      "Login pages reached from an unexpected email/SMS. When a page asks for credentials, navigate to the service yourself via a bookmark instead.",
    ],
  },
];

/** Static, purely educational security guide. */
export default function GuidePage() {
  return (
    <div className="page">
      <header className="page-head center">
        <h1>Security Guide</h1>
        <p>
          Practical patterns for recognizing hostile URLs. Educational reference — the
          analyzer above automates many of these checks.
        </p>
      </header>

      <div className="guide-grid">
        {TOPICS.map((t) => (
          <article key={t.title} className="card-glass guide-card">
            <span className="guide-icon" aria-hidden="true">{t.icon}</span>
            <h2>{t.title}</h2>
            {t.body.map((p, i) => (
              <p key={i}>{p}</p>
            ))}
          </article>
        ))}
      </div>

      <section className="card-glass">
        <h2>General rules of thumb</h2>
        <ul className="tips">
          <li>✓ Type sensitive logins through bookmarks, never through emailed links.</li>
          <li>✓ Check the registrable domain — the part just before the first single slash.</li>
          <li>✓ Treat HTTPS as encryption, not endorsement.</li>
          <li>✓ Be suspicious of urgency; legitimate services rarely threaten account loss in hours.</li>
          <li>✓ Enable multi-factor authentication — it saves you when a password leaks.</li>
        </ul>
      </section>
    </div>
  );
}

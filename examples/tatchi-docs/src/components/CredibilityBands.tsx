type CredibilityLogo = {
  label: string
  tone?: 'ink' | 'blue' | 'slate'
}

const trustedLogos: CredibilityLogo[] = [
  { label: 'AtlasPay', tone: 'ink' },
  { label: 'Coinline', tone: 'blue' },
  { label: 'VisaFlow', tone: 'blue' },
  { label: 'WireGrid', tone: 'ink' },
  { label: 'Neural Labs', tone: 'slate' },
  { label: 'TeleLink', tone: 'blue' },
  { label: 'Toku Core', tone: 'blue' },
  { label: 'Kasi', tone: 'ink' },
  { label: 'MoraBank', tone: 'slate' },
  { label: 'Fomo Labs', tone: 'ink' },
  { label: 'Ruvo', tone: 'blue' },
  { label: 'Sora Systems', tone: 'ink' },
]

const investorLogos: CredibilityLogo[] = [
  { label: 'Ribbit Capital', tone: 'ink' },
  { label: 'Franklin Templeton', tone: 'slate' },
  { label: 'Nyca', tone: 'ink' },
  { label: 'Lightspeed', tone: 'slate' },
  { label: 'First Round', tone: 'ink' },
  { label: 'HF0', tone: 'slate' },
]

function renderLogo(logo: CredibilityLogo): React.JSX.Element {
  const tone = logo.tone ?? 'ink'
  return (
    <li key={logo.label} className={`credibility-logo credibility-logo--${tone}`}>
      {logo.label}
    </li>
  )
}

export function CredibilityBands(): React.JSX.Element {
  return (
    <section className="credibility-bands" aria-label="Credibility">
      <article className="credibility-band" aria-labelledby="credibility-trusted-title">
        <p id="credibility-trusted-title" className="credibility-band__title">
          Trusted by 40,000+ enterprises and developers
        </p>
        <ul className="credibility-band__logos" aria-label="Trusted by">
          {trustedLogos.map(renderLogo)}
        </ul>
      </article>

      <article className="credibility-band" aria-labelledby="credibility-backed-title">
        <p id="credibility-backed-title" className="credibility-band__title">
          Backed by the best
        </p>
        <ul className="credibility-band__logos credibility-band__logos--investors" aria-label="Backed by">
          {investorLogos.map(renderLogo)}
        </ul>
      </article>
    </section>
  )
}

export default CredibilityBands

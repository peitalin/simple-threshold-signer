import { useVitepressRouter } from '../hooks/useVitepressRouter'

type SecurityLink = {
  label: string
  detail: string
  to: string
}

const securityLinks: SecurityLink[] = [
  {
    label: 'Security Model',
    detail: 'Review threat boundaries and defense-in-depth controls.',
    to: '/docs/concepts/security-model',
  },
  {
    label: 'Threshold Signing',
    detail: 'Inspect enrollment and distributed signing flow details.',
    to: '/docs/concepts/threshold-signing',
  },
  {
    label: 'SecureConfirm WebAuthn',
    detail: 'Understand challenge construction and verification semantics.',
    to: '/docs/concepts/secureconfirm-webauthn',
  },
]

export function SecurityProofStrip(): React.JSX.Element {
  const { linkProps } = useVitepressRouter()

  return (
    <section className="security-proof" aria-labelledby="security-proof-title">
      <header className="security-proof__header">
        <p className="security-proof__eyebrow">Security and architecture</p>
        <h2 id="security-proof-title" className="security-proof__title">Technical credibility with direct documentation paths</h2>
      </header>
      <div className="security-proof__links">
        {securityLinks.map((item) => {
          const props = linkProps(item.to)
          return (
            <a key={item.label} className="security-proof__link" href={props.href} onClick={props.onClick}>
              <strong>{item.label}</strong>
              <span>{item.detail}</span>
            </a>
          )
        })}
      </div>
    </section>
  )
}

export default SecurityProofStrip

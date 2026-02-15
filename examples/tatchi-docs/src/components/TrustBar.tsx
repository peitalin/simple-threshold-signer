import { Fingerprint, ShieldCheck, Wallet } from 'lucide-react'

type TrustItem = {
  title: string
  description: string
  icon: React.ComponentType<{ className?: string; size?: number; 'aria-hidden'?: boolean }>
}

const trustItems: TrustItem[] = [
  {
    title: 'Passkey-native UX',
    description: 'No extension installs or popup handoffs in core wallet flows.',
    icon: Fingerprint,
  },
  {
    title: 'Threshold Signing',
    description: 'Distributed signing primitives with policy-focused authorization.',
    icon: ShieldCheck,
  },
  {
    title: 'Embedded Wallet SDK',
    description: 'Developer-first integration path with quickstart docs and examples.',
    icon: Wallet,
  },
]

export function TrustBar(): React.JSX.Element {
  return (
    <section className="trust-strip" aria-labelledby="trust-strip-title">
      <header className="trust-strip__header">
        <p className="trust-strip__eyebrow">Why teams choose Tatchi</p>
        <h2 id="trust-strip-title" className="trust-strip__title">Built for product velocity and signing integrity</h2>
      </header>
      <div className="trust-strip__grid">
        {trustItems.map((item) => (
          <article key={item.title} className="trust-strip__card">
            <item.icon className="trust-strip__icon" size={18} aria-hidden />
            <h3>{item.title}</h3>
            <p>{item.description}</p>
          </article>
        ))}
      </div>
    </section>
  )
}

export default TrustBar

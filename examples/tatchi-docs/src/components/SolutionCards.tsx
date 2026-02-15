import { useVitepressRouter } from '../hooks/useVitepressRouter'

type SolutionCard = {
  title: string
  description: string
  to: string
}

const solutionCards: SolutionCard[] = [
  {
    title: 'Consumer Apps',
    description: 'Keep wallet flows in your app to reduce onboarding drop-off.',
    to: '/solutions/#consumer-apps',
  },
  {
    title: 'Stablecoin Payments',
    description: 'Embed confirmation and signing directly in payment journeys.',
    to: '/solutions/#stablecoin-payments',
  },
  {
    title: 'Treasury and Payouts',
    description: 'Use policy-based approvals for internal transfers and disbursements.',
    to: '/solutions/#treasury-and-payouts',
  },
]

export function SolutionCards(): React.JSX.Element {
  const { linkProps } = useVitepressRouter()

  return (
    <section className="solution-cards" aria-labelledby="solution-cards-title">
      <header className="solution-cards__header">
        <p className="solution-cards__eyebrow">Solutions</p>
        <h2 id="solution-cards-title" className="solution-cards__title">Designed for teams shipping security-sensitive flows</h2>
      </header>
      <div className="solution-cards__grid">
        {solutionCards.map((solution) => {
          const props = linkProps(solution.to)
          return (
            <a key={solution.title} className="solution-cards__item" href={props.href} onClick={props.onClick}>
              <h3>{solution.title}</h3>
              <p>{solution.description}</p>
            </a>
          )
        })}
      </div>
    </section>
  )
}

export default SolutionCards

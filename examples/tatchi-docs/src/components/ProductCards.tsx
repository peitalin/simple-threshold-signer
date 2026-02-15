import { useVitepressRouter } from '../hooks/useVitepressRouter'

type ProductModule = {
  title: string
  description: string
  to: string
}

const productModules: ProductModule[] = [
  {
    title: 'Embedded Wallets',
    description: 'Passkey-first wallet onboarding and in-app signing journeys.',
    to: '/products/',
  },
  {
    title: 'Threshold Signing',
    description: 'Policy-aware authorization and key-share based transaction signing.',
    to: '/docs/concepts/threshold-signing',
  },
  {
    title: 'SecureConfirm WebAuthn',
    description: 'Onchain-verifiable challenge flows for sensitive transaction approvals.',
    to: '/docs/concepts/secureconfirm-webauthn',
  },
]

export function ProductCards(): React.JSX.Element {
  const { linkProps } = useVitepressRouter()

  return (
    <section className="product-cards" aria-labelledby="product-cards-title">
      <header className="product-cards__header">
        <p className="product-cards__eyebrow">Products</p>
        <h2 id="product-cards-title" className="product-cards__title">Composable wallet and signing building blocks</h2>
      </header>
      <div className="product-cards__grid">
        {productModules.map((module) => {
          const props = linkProps(module.to)
          return (
            <a key={module.title} className="product-cards__item" href={props.href} onClick={props.onClick}>
              <h3>{module.title}</h3>
              <p>{module.description}</p>
            </a>
          )
        })}
      </div>
    </section>
  )
}

export default ProductCards

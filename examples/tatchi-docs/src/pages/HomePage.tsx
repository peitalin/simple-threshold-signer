import React from 'react'
import { CredibilityBands } from '../components/CredibilityBands'
import { FinalCTA } from '../components/FinalCTA'
import { Footer } from '../components/Footer'
import { HomeHero } from '../components/HomeHero'
import NearLogoBg from '../components/NearLogoBg'
import NavbarStatic from '../components/Navbar/NavbarStatic'
import { ProductCards } from '../components/ProductCards'
import { SecurityProofStrip } from '../components/SecurityProofStrip'
import { SolutionCards } from '../components/SolutionCards'
import { TrustBar } from '../components/TrustBar'
import { useRevealOnIdle } from '../hooks/useRevealOnIdle'

// Defer loading the DemoPasskeyColumn until after first paint/idle
const DemoPasskeyColumnLazy = React.lazy(() => import('../components/DemoPasskeyColumn').then((m) => ({ default: m.DemoPasskeyColumn })))

const SectionPlaceholder: React.FC = () => (
  <div style={{ minHeight: 360 }} />
)

const LazyPasskeySection: React.FC = () => {
  const show = useRevealOnIdle()
  return (
    <div className="layout-column-right">
      <NearLogoBg />
      <div className="constrained-column">
        {show ? (
          <React.Suspense fallback={<SectionPlaceholder />}>
            <DemoPasskeyColumnLazy />
          </React.Suspense>
        ) : (
          <SectionPlaceholder />
        )}
      </div>
    </div>
  )
}

export function HomePage(): React.JSX.Element {
  return (
    <>
      <NavbarStatic />
      <div className="layout-root">
        <div className="card one">
          <div className="constrained-column">
            <HomeHero />
          </div>
        </div>

        <div className="card two">
          <LazyPasskeySection />
        </div>

        <div className="card three">
          <div className="single-column-content marketing-stack">
            <CredibilityBands />
            <section className="marketing-rail" aria-label="Platform capabilities">
              <TrustBar />
              <ProductCards />
              <SolutionCards />
              <SecurityProofStrip />
              <FinalCTA />
            </section>
          </div>
        </div>

        <div className="card five">
          <div className="full-bleed">
            <Footer />
          </div>
        </div>
      </div>
    </>
  )
}

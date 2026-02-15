import { Linkedin, Youtube } from 'lucide-react'
import React from 'react'
import { useVitepressRouter } from '../hooks/useVitepressRouter'
import './Footer.css'
import Github from './icons/Github'
import NearLogo from './icons/NearLogoWithText'
import TatchiLogo from './icons/TatchiLogo'
import Twitter from './icons/Twitter'

type FooterLink = {
  label: string
  to: string
}

type FooterGroup = {
  heading: string
  links: FooterLink[]
}

const footerGroups: FooterGroup[] = [
  {
    heading: 'Products',
    links: [
      { label: 'Embedded Wallets', to: '/products/' },
      { label: 'Threshold Signing', to: '/docs/concepts/threshold-signing' },
      { label: 'SecureConfirm WebAuthn', to: '/docs/concepts/secureconfirm-webauthn' },
      { label: 'Developer Docs', to: '/docs/getting-started/overview' },
    ],
  },
  {
    heading: 'Solutions',
    links: [
      { label: 'Consumer Apps', to: '/solutions/#consumer-apps' },
      { label: 'Stablecoin Payments', to: '/solutions/#stablecoin-payments' },
      { label: 'Treasury & Payouts', to: '/solutions/#treasury-and-payouts' },
      { label: 'Smart Accounts', to: '/solutions/' },
    ],
  },
  {
    heading: 'Support',
    links: [
      { label: 'Help Center', to: '/docs/getting-started/overview' },
      { label: 'Contact Sales', to: '/contact/' },
      { label: 'Security Model', to: '/docs/concepts/security-model' },
      { label: 'Architecture', to: '/docs/concepts/threshold-signing' },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'About', to: '/company/' },
      { label: 'Pricing', to: '/pricing/' },
      { label: 'Documentation', to: '/docs/getting-started/overview' },
      { label: 'Get in Touch', to: '/contact/' },
    ],
  },
]

function onSubscribeSubmit(event: React.FormEvent<HTMLFormElement>): void {
  event.preventDefault()
}

export function Footer(): React.JSX.Element {
  const { linkProps } = useVitepressRouter()
  const homeProps = linkProps('/')
  const privacyProps = linkProps('/company/')
  const termsProps = linkProps('/company/')
  const cookiesProps = linkProps('/company/')

  return (
    <footer className="app-footer" aria-label="Site footer">
      <div className="app-footer__bg-glow app-footer__bg-glow--left" aria-hidden />
      <div className="app-footer__bg-glow app-footer__bg-glow--right" aria-hidden />

      <div className="app-footer__inner">
        <section className="app-footer__lead" aria-labelledby="footer-newsletter-title">
          <a className="app-footer__brand" href={homeProps.href} onClick={homeProps.onClick} aria-label="Tatchi home">
            <TatchiLogo size={26} strokeWidth={1.2} />
            <span>Tatchi</span>
          </a>

          <div className="app-footer__newsletter">
            <h2 id="footer-newsletter-title">Don&apos;t miss an update</h2>
            <p>Product releases, security notes, and implementation guidance for wallet teams.</p>
            <form className="app-footer__subscribe" onSubmit={onSubscribeSubmit}>
              <label className="app-footer__sr-only" htmlFor="footer-email-input">
                Enter email for updates
              </label>
              <input id="footer-email-input" type="email" placeholder="Enter your email" autoComplete="email" />
              <button type="submit">Subscribe</button>
            </form>
            <small>
              By subscribing, you acknowledge our{' '}
              <a href={privacyProps.href} onClick={privacyProps.onClick}>
                Privacy Policy
              </a>
              .
            </small>
          </div>

          <a
            href="https://near.org"
            target="_blank"
            rel="noopener noreferrer"
            className="app-footer__near"
            aria-label="Built on NEAR"
          >
            Built on <NearLogo className="app-footer__near-logo" />
          </a>
        </section>

        <nav className="app-footer__nav" aria-label="Footer navigation">
          {footerGroups.map((group) => (
            <section className="app-footer__col" key={group.heading}>
              <h3 className="app-footer__heading">{group.heading}</h3>
              {group.links.map((link) => {
                const props = linkProps(link.to)
                return (
                  <a key={link.label} href={props.href} onClick={props.onClick}>
                    {link.label}
                  </a>
                )
              })}
            </section>
          ))}
        </nav>

        <div className="app-footer__bottom">
          <div className="app-footer__socials" aria-label="Social links">
            <a href="https://x.com/lowerarchy" target="_blank" rel="noopener noreferrer" aria-label="X">
              <Twitter size={16} aria-hidden />
            </a>
            <a href="https://github.com/web3-authn/tatchi" target="_blank" rel="noopener noreferrer" aria-label="GitHub">
              <Github size={16} aria-hidden />
            </a>
            <a href="https://www.linkedin.com/company/near-protocol" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn">
              <Linkedin size={16} aria-hidden />
            </a>
            <a href="https://www.youtube.com/@NEARProtocol" target="_blank" rel="noopener noreferrer" aria-label="YouTube">
              <Youtube size={16} aria-hidden />
            </a>
          </div>

          <div className="app-footer__legal">
            <p>Copyright © {new Date().getFullYear()} Tatchi, Inc. All rights reserved.</p>
            <div className="app-footer__legal-links">
              <a href={termsProps.href} onClick={termsProps.onClick}>Terms &amp; Conditions</a>
              <a href={privacyProps.href} onClick={privacyProps.onClick}>Privacy Policy</a>
              <a href={cookiesProps.href} onClick={cookiesProps.onClick}>Cookies</a>
            </div>
          </div>

          <div className="app-footer__badges" aria-label="Compliance certifications">
            <span>SOC 2</span>
            <span>GDPR</span>
            <span>CCPA</span>
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer

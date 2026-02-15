import { useState } from 'react'
import { LibraryBig, MessageSquareMore } from 'lucide-react'
import { TouchIcon, useTheme } from '@tatchi-xyz/sdk/react'
import { ArrowRightAnim } from './ArrowRightAnim'
import CopyButton from './CopyButton'
import { useVitepressRouter } from '../hooks/useVitepressRouter'
import { mobilePressHandlers } from '../utils/press'

type PackageManager = 'npm' | 'pnpm' | 'bun'

function getInstallCommand(packageManager: PackageManager): string {
  switch (packageManager) {
    case 'npm':
      return 'npm install @tatchi-xyz/sdk'
    case 'pnpm':
      return 'pnpm add @tatchi-xyz/sdk'
    case 'bun':
      return 'bun add @tatchi-xyz/sdk'
    default: {
      const exhaustive: never = packageManager
      throw new Error(`Unsupported package manager: ${exhaustive}`)
    }
  }
}

function highlightInstallCommand(command: string): string {
  return command
    .replace(/^(npm|pnpm|bun)/, '<span class="code-kw-pm">$1</span>')
    .replace(/(@tatchi-xyz\/sdk)/, '<span class="code-kw-pkg">$1</span>')
}

export function HomeHero(): React.JSX.Element {
  const [packageManager, setPackageManager] = useState<PackageManager>('npm')
  const { linkProps } = useVitepressRouter()
  const { theme } = useTheme()

  const installBlockCmd = getInstallCommand(packageManager)
  const highlightedInstall = highlightInstallCommand(installBlockCmd)
  const getStartedProps = linkProps('/docs/getting-started/installation')
  const contactSalesProps = linkProps('/contact/')

  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <h1 id="hero-title" className="hero-title">
          Embedded wallets that ship faster
          <span className="touch-icon-pattern-position" aria-hidden="true">
            <TouchIcon
              style={{ color: theme === 'dark' ? 'var(--w3a-colors-surface)' : 'var(--w3a-colors-surface2)' }}
              strokeWidth={11}
              width={124}
              height={124}
            />
          </span>
        </h1>
        <h2 className="hero-subtitle">
          Tatchi gives product and platform teams passkey-native wallet flows without extension installs or popup handoffs.
        </h2>
        <p className="hero-description">
          Launch faster with policy-based threshold signing, keep conversion in-app, and keep security controls one click from your docs.
        </p>
        <p className="hero-proof">
          Trusted architecture: WebAuthn confirmation challenges, threshold signing, and explicit security model documentation.
        </p>
        <div className="hero-ctas">
          <a
            className="cta-button cta-primary cta-3"
            href={getStartedProps.href}
            onClick={getStartedProps.onClick}
            aria-label="Get started with Tatchi documentation"
          >
            <LibraryBig size={24} className="cta-icon" aria-hidden="true" />
            <span>Get Started</span>
            <ArrowRightAnim className="cta-icon" size={16} />
          </a>
          <a
            className="cta-button cta-secondary cta-3"
            href={contactSalesProps.href}
            onClick={contactSalesProps.onClick}
            aria-label="Contact sales"
          >
            <MessageSquareMore size={22} className="cta-icon" aria-hidden="true" />
            <span>Contact Sales</span>
            <ArrowRightAnim className="cta-icon" size={16} />
          </a>
        </div>
      </section>

      <section className="hero-intro" aria-label="Install the SDK">
        <div className="install-panel" role="group" aria-label="Install command (CLI)">
          <div className="install-header">
            <div className="install-header-left">
              <div className="install-tabs" role="tablist" aria-label="Package managers (CLI)">
                {(['npm', 'pnpm', 'bun'] as const).map((k) => (
                  <button
                    key={k}
                    role="tab"
                    aria-selected={packageManager === k}
                    className={`install-tab${packageManager === k ? ' active' : ''}`}
                    {...mobilePressHandlers(() => setPackageManager(k))}
                  >
                    {k}
                  </button>
                ))}
              </div>
            </div>
            <CopyButton
              text={installBlockCmd}
              size={16}
              ariaLabel="Copy install command"
            />
          </div>
          <div className="install-body">
            <pre className="code-block code-block--dark"><code dangerouslySetInnerHTML={{ __html: highlightedInstall }} /></pre>
          </div>
        </div>
      </section>
    </>
  )
}

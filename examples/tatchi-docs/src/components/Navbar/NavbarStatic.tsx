import React from 'react'
import { ChevronDown, Menu, X } from 'lucide-react'
import { MoonIcon, SunIcon, useTheme } from '@tatchi-xyz/sdk/react'
import TatchiLogo from '../icons/TatchiLogo'
import { useVitepressRouter } from '../../hooks/useVitepressRouter'
import './Navbar.css'

type DropdownId = 'products' | 'solutions'

type DropdownItem = {
  title: string
  description: string
  to: string
}

type DropdownSection = {
  heading: string
  items: DropdownItem[]
}

type DropdownConfig = {
  id: DropdownId
  label: string
  rootTo: string
  allLabel: string
  sections: DropdownSection[]
}

type DropdownFocusTarget = 'first' | 'last'

const productSections: DropdownSection[] = [
  {
    heading: 'Wallets',
    items: [
      {
        title: 'Embedded Wallets',
        description: 'Passkey wallet flows that stay inside your app UI',
        to: '/docs/getting-started/overview',
      },
      {
        title: 'Account Sync',
        description: 'Restore and link accounts across devices',
        to: '/docs/concepts/passkey-scope',
      },
    ],
  },
  {
    heading: 'Signing & Security',
    items: [
      {
        title: 'Threshold Signing',
        description: 'Distributed signing with strict policy controls',
        to: '/docs/concepts/threshold-signing',
      },
      {
        title: 'SecureConfirm WebAuthn',
        description: 'Onchain-verifiable confirmation challenges',
        to: '/docs/concepts/secureconfirm-webauthn',
      },
      {
        title: 'Security Model',
        description: 'Defense-in-depth and browser policy boundaries',
        to: '/docs/concepts/security-model',
      },
    ],
  },
]

const solutionSections: DropdownSection[] = [
  {
    heading: 'By Use Case',
    items: [
      {
        title: 'Consumer Apps',
        description: 'Passkey wallets without popups or extension installs',
        to: '/solutions/#consumer-apps',
      },
      {
        title: 'Stablecoin Payments',
        description: 'In-app signing and transaction confirmation flows',
        to: '/solutions/#stablecoin-payments',
      },
      {
        title: 'Treasury & Payouts',
        description: 'Policy-based approvals for internal transfers',
        to: '/solutions/#treasury-and-payouts',
      },
      {
        title: 'Recovery & Device Linking',
        description: 'Cross-device account continuity without seed phrases',
        to: '/solutions/#recovery-and-device-linking',
      },
    ],
  },
  {
    heading: 'By Team',
    items: [
      {
        title: 'Product Teams',
        description: 'Friction-light wallet UX patterns for conversion',
        to: '/solutions/#product-teams',
      },
      {
        title: 'Security Teams',
        description: 'SecureConfirm and threshold policy guardrails',
        to: '/solutions/#security-teams',
      },
      {
        title: 'Platform Teams',
        description: 'Reusable signing primitives across multiple apps',
        to: '/solutions/#platform-teams',
      },
    ],
  },
]

const dropdownConfigs: DropdownConfig[] = [
  {
    id: 'products',
    label: 'Products',
    rootTo: '/products/',
    allLabel: 'View all products',
    sections: productSections,
  },
  {
    id: 'solutions',
    label: 'Solutions',
    rootTo: '/solutions/',
    allLabel: 'View all solutions',
    sections: solutionSections,
  },
]

function isClickInsideRoot(target: EventTarget | null, root: HTMLElement | null): boolean {
  return !!(target instanceof Node && root && root.contains(target))
}

function getMenuItems(panel: HTMLDivElement | null, id: DropdownId | null): HTMLElement[] {
  if (!panel || !id) return []
  return Array.from(panel.querySelectorAll<HTMLElement>(`[data-dropdown-view="${id}"] a[role="menuitem"]`))
}

function readDocumentTheme(): 'light' | 'dark' {
  if (typeof document === 'undefined') return 'dark'
  const attr = document.documentElement.getAttribute('data-w3a-theme')
  if (attr === 'light' || attr === 'dark') return attr
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}

function applyDocumentTheme(next: 'light' | 'dark'): void {
  if (typeof document === 'undefined' || typeof window === 'undefined') return
  document.documentElement.classList.toggle('dark', next === 'dark')
  document.documentElement.setAttribute('data-w3a-theme', next)
  try {
    window.localStorage?.setItem?.('vitepress-theme-appearance', next)
  } catch {}
  window.dispatchEvent(new CustomEvent<'light' | 'dark'>('w3a:appearance', { detail: next }))
}

export function NavbarStatic(): React.JSX.Element {
  const OPEN_DELAY_MS = 0
  const CLOSE_DELAY_MS = 280
  const CONTENT_SWITCH_MS = 660
  const SCROLL_THRESHOLD_PX = 8

  const { theme, setTheme } = useTheme()
  const { linkProps } = useVitepressRouter()
  const rootRef = React.useRef<HTMLElement | null>(null)
  const shellRef = React.useRef<HTMLDivElement | null>(null)
  const dropdownButtonRefs = React.useRef<Record<DropdownId, HTMLButtonElement | null>>({
    products: null,
    solutions: null,
  })
  const dropdownPanelRef = React.useRef<HTMLDivElement | null>(null)
  const openTimerRef = React.useRef<number | null>(null)
  const closeTimerRef = React.useRef<number | null>(null)
  const switchTimerRef = React.useRef<number | null>(null)
  const [openDropdown, setOpenDropdown] = React.useState<DropdownId | null>(null)
  const [visibleDropdown, setVisibleDropdown] = React.useState<DropdownId | null>(null)
  const [leavingDropdown, setLeavingDropdown] = React.useState<DropdownId | null>(null)
  const [dropdownNotchLeft, setDropdownNotchLeft] = React.useState<number>(120)
  const [hasScrolled, setHasScrolled] = React.useState<boolean>(false)
  const [localTheme, setLocalTheme] = React.useState<'light' | 'dark'>(() => readDocumentTheme())
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState<boolean>(false)
  const [isMobileProductsOpen, setIsMobileProductsOpen] = React.useState<boolean>(false)
  const [isMobileSolutionsOpen, setIsMobileSolutionsOpen] = React.useState<boolean>(false)

  const resolvedTheme: 'light' | 'dark' = (typeof setTheme === 'function' ? theme : localTheme) === 'dark' ? 'dark' : 'light'

  const onToggleTheme = React.useCallback(() => {
    const next: 'light' | 'dark' = resolvedTheme === 'dark' ? 'light' : 'dark'
    if (typeof setTheme === 'function') {
      setTheme(next)
      return
    }
    applyDocumentTheme(next)
    setLocalTheme(next)
  }, [resolvedTheme, setTheme])

  const clearDropdownTimers = React.useCallback(() => {
    if (openTimerRef.current !== null) {
      window.clearTimeout(openTimerRef.current)
      openTimerRef.current = null
    }
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current)
      closeTimerRef.current = null
    }
  }, [])

  const clearContentSwitchTimer = React.useCallback(() => {
    if (switchTimerRef.current !== null) {
      window.clearTimeout(switchTimerRef.current)
      switchTimerRef.current = null
    }
  }, [])

  const updateDropdownNotchPosition = React.useCallback((id: DropdownId) => {
    const shell = shellRef.current
    const button = dropdownButtonRefs.current[id]
    if (!shell || !button) return

    const shellRect = shell.getBoundingClientRect()
    const buttonRect = button.getBoundingClientRect()
    const center = buttonRect.left + (buttonRect.width / 2) - shellRect.left
    const clampedCenter = Math.min(Math.max(center, 42), shellRect.width - 42)
    setDropdownNotchLeft(clampedCenter)
  }, [])

  const scheduleOpenDropdown = React.useCallback((id: DropdownId, delayMs: number = OPEN_DELAY_MS) => {
    if (isMobileMenuOpen) return

    const effectiveDelayMs = openDropdown && openDropdown !== id ? 0 : delayMs

    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current)
      closeTimerRef.current = null
    }
    if (openTimerRef.current !== null) {
      window.clearTimeout(openTimerRef.current)
      openTimerRef.current = null
    }

    openTimerRef.current = window.setTimeout(() => {
      setOpenDropdown(id)
      updateDropdownNotchPosition(id)
      openTimerRef.current = null
    }, effectiveDelayMs)
  }, [isMobileMenuOpen, openDropdown, updateDropdownNotchPosition])

  const scheduleCloseDropdown = React.useCallback((delayMs: number = CLOSE_DELAY_MS) => {
    if (isMobileMenuOpen) return
    if (openTimerRef.current !== null) {
      window.clearTimeout(openTimerRef.current)
      openTimerRef.current = null
    }
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current)
      closeTimerRef.current = null
    }
    closeTimerRef.current = window.setTimeout(() => {
      setOpenDropdown(null)
      closeTimerRef.current = null
    }, delayMs)
  }, [isMobileMenuOpen])

  const closeMenus = React.useCallback(() => {
    clearDropdownTimers()
    clearContentSwitchTimer()
    setOpenDropdown(null)
    setVisibleDropdown(null)
    setLeavingDropdown(null)
    setIsMobileMenuOpen(false)
    setIsMobileProductsOpen(false)
    setIsMobileSolutionsOpen(false)
  }, [clearDropdownTimers, clearContentSwitchTimer])

  React.useEffect(() => {
    return () => {
      clearDropdownTimers()
      clearContentSwitchTimer()
    }
  }, [clearDropdownTimers, clearContentSwitchTimer])

  React.useEffect(() => {
    const onScroll = () => {
      setHasScrolled(window.scrollY > SCROLL_THRESHOLD_PX)
    }

    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
    }
  }, [SCROLL_THRESHOLD_PX])

  React.useEffect(() => {
    if (typeof setTheme === 'function') return
    if (typeof document === 'undefined' || typeof window === 'undefined') return

    const read = () => setLocalTheme(readDocumentTheme())
    read()

    const mo = new MutationObserver(read)
    mo.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', 'data-w3a-theme'],
    })

    const onAppearance = (e: Event) => {
      const next = (e as CustomEvent<'light' | 'dark'>)?.detail
      if (next === 'light' || next === 'dark') setLocalTheme(next)
      else read()
    }

    window.addEventListener('w3a:appearance', onAppearance as EventListener)
    window.addEventListener('w3a:set-theme', onAppearance as EventListener)
    return () => {
      mo.disconnect()
      window.removeEventListener('w3a:appearance', onAppearance as EventListener)
      window.removeEventListener('w3a:set-theme', onAppearance as EventListener)
    }
  }, [setTheme])

  React.useEffect(() => {
    clearContentSwitchTimer()

    if (!openDropdown) {
      setLeavingDropdown(null)
      setVisibleDropdown(null)
      return
    }

    if (visibleDropdown && visibleDropdown !== openDropdown) {
      setLeavingDropdown(visibleDropdown)
      setVisibleDropdown(openDropdown)
      switchTimerRef.current = window.setTimeout(() => {
        setLeavingDropdown(null)
        switchTimerRef.current = null
      }, CONTENT_SWITCH_MS)
      return
    }

    if (visibleDropdown !== openDropdown) {
      setVisibleDropdown(openDropdown)
    }
    setLeavingDropdown(null)
  }, [openDropdown, visibleDropdown, clearContentSwitchTimer])

  React.useEffect(() => {
    if (!openDropdown) return

    const onResize = () => {
      updateDropdownNotchPosition(openDropdown)
    }

    onResize()
    window.addEventListener('resize', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
    }
  }, [openDropdown, updateDropdownNotchPosition])

  const getNavLinkProps = React.useCallback((to: string) => {
    const props = linkProps(to)
    return {
      href: props.href,
      onClick: (e: React.MouseEvent<HTMLAnchorElement>) => {
        props.onClick(e)
        closeMenus()
      },
    }
  }, [linkProps, closeMenus])

  const openDropdownFromKeyboard = React.useCallback((id: DropdownId, focusTarget: DropdownFocusTarget = 'first') => {
    clearDropdownTimers()
    clearContentSwitchTimer()
    setOpenDropdown(id)
    updateDropdownNotchPosition(id)

    requestAnimationFrame(() => {
      const menuItems = getMenuItems(dropdownPanelRef.current, id)
      if (!menuItems.length) return

      if (focusTarget === 'last') {
        menuItems[menuItems.length - 1]?.focus()
        return
      }
      menuItems[0]?.focus()
    })
  }, [clearDropdownTimers, clearContentSwitchTimer, updateDropdownNotchPosition])

  const onDropdownButtonKeyDown = React.useCallback((e: React.KeyboardEvent<HTMLButtonElement>, id: DropdownId) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      closeMenus()
      return
    }

    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      openDropdownFromKeyboard(id, 'first')
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault()
      openDropdownFromKeyboard(id, 'last')
    }
  }, [closeMenus, openDropdownFromKeyboard])

  const onDropdownPanelKeyDown = React.useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    const id = visibleDropdown ?? openDropdown
    const menuItems = getMenuItems(dropdownPanelRef.current, id)
    if (!menuItems.length) return

    const activeIndex = menuItems.findIndex((item) => item === document.activeElement)

    if (e.key === 'Escape') {
      e.preventDefault()
      closeMenus()
      if (id) {
        dropdownButtonRefs.current[id]?.focus()
      }
      return
    }

    if (e.key === 'Home') {
      e.preventDefault()
      menuItems[0]?.focus()
      return
    }

    if (e.key === 'End') {
      e.preventDefault()
      menuItems[menuItems.length - 1]?.focus()
      return
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      const nextIndex = activeIndex < 0 ? 0 : (activeIndex + 1) % menuItems.length
      menuItems[nextIndex]?.focus()
      return
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault()
      const nextIndex = activeIndex <= 0 ? menuItems.length - 1 : activeIndex - 1
      menuItems[nextIndex]?.focus()
    }
  }, [closeMenus, openDropdown, visibleDropdown])

  React.useEffect(() => {
    if (!openDropdown && !isMobileMenuOpen) return

    const onPointerDown = (e: PointerEvent) => {
      if (isClickInsideRoot(e.target, rootRef.current)) return
      closeMenus()
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      closeMenus()
    }

    window.addEventListener('pointerdown', onPointerDown)
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('pointerdown', onPointerDown)
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [closeMenus, isMobileMenuOpen, openDropdown])

  const docsProps = getNavLinkProps('/docs/getting-started/overview')
  const homeProps = getNavLinkProps('/')
  const productsRootProps = getNavLinkProps('/products/')
  const solutionsRootProps = getNavLinkProps('/solutions/')
  const pricingProps = getNavLinkProps('/pricing/')
  const companyProps = getNavLinkProps('/company/')
  const contactSalesProps = getNavLinkProps('/contact/')
  const getStartedProps = getNavLinkProps('/docs/getting-started/installation')

  const dropdownAriaConfig = dropdownConfigs.find((config) => config.id === (visibleDropdown ?? openDropdown)) ?? null
  const activeDropdownId = visibleDropdown ?? openDropdown
  const dropdownSurfaceStyle = React.useMemo(() => {
    return { '--navbar-dropdown-notch-left': `${dropdownNotchLeft}px` } as React.CSSProperties
  }, [dropdownNotchLeft])

  function renderDropdownTrigger(config: DropdownConfig): React.JSX.Element {
    const isOpen = openDropdown === config.id

    return (
      <div
        key={config.id}
        className="navbar-static__group"
        onMouseEnter={() => scheduleOpenDropdown(config.id)}
        onMouseLeave={() => scheduleCloseDropdown()}
        onFocusCapture={() => scheduleOpenDropdown(config.id, 0)}
        onBlurCapture={(e) => {
          const next = e.relatedTarget
          if (next instanceof Node && rootRef.current?.contains(next)) return
          scheduleCloseDropdown(0)
        }}
      >
        <button
          type="button"
          ref={(el) => { dropdownButtonRefs.current[config.id] = el }}
          className={`navbar-static__link navbar-static__link--button${isOpen ? ' is-active' : ''}`}
          aria-expanded={isOpen}
          aria-haspopup="menu"
          aria-controls={`navbar-dropdown-${config.id}`}
          onClick={() => {
            clearDropdownTimers()
            clearContentSwitchTimer()
            setOpenDropdown((open) => {
              if (open === config.id) return null
              updateDropdownNotchPosition(config.id)
              return config.id
            })
          }}
          onKeyDown={(e) => onDropdownButtonKeyDown(e, config.id)}
        >
          <span>{config.label}</span>
          <ChevronDown size={16} className={`navbar-static__chevron${isOpen ? ' is-open' : ''}`} aria-hidden />
        </button>
      </div>
    )
  }

  return (
    <nav ref={rootRef} className="navbar-static" aria-label="Primary">
      <div ref={shellRef} className={`navbar-static__shell${hasScrolled ? ' is-scrolled' : ''}`}>
        <div className="navbar-static__left">
          <a className="navbar-static__brand" href={homeProps.href} onClick={homeProps.onClick} aria-label="Tatchi home">
            <TatchiLogo size={26} strokeWidth={1.2} />
            <span>Tatchi</span>
          </a>
        </div>

        <div className="navbar-static__center">
          <div className="navbar-static__links">
            {dropdownConfigs.map(renderDropdownTrigger)}
            <a className="navbar-static__link" href={docsProps.href} onClick={docsProps.onClick}>Documentation</a>
            <a className="navbar-static__link" href={pricingProps.href} onClick={pricingProps.onClick}>Pricing</a>
            <a className="navbar-static__link" href={companyProps.href} onClick={companyProps.onClick}>Company</a>
          </div>
        </div>

        <div className="navbar-static__right">
          <div className="navbar-static__actions">
            <a
              className="navbar-static__pill navbar-static__pill--ghost"
              href="https://github.com/web3-authn/tatchi"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
            <a
              className="navbar-static__pill navbar-static__pill--ghost"
              href={contactSalesProps.href}
              onClick={contactSalesProps.onClick}
            >
              Contact Sales
            </a>
            <a
              className="navbar-static__pill navbar-static__pill--solid"
              href={getStartedProps.href}
              onClick={getStartedProps.onClick}
            >
              Get Started
            </a>
            <button
              type="button"
              className="navbar-static__theme-toggle"
              onClick={onToggleTheme}
              aria-label="Toggle dark mode"
              title="Toggle dark mode"
            >
              {resolvedTheme === 'dark' ? <SunIcon size={18} strokeWidth={2} aria-hidden /> : <MoonIcon size={18} strokeWidth={2} aria-hidden />}
            </button>
            <button
              type="button"
              className="navbar-static__mobile-toggle"
              aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
              onClick={() => setIsMobileMenuOpen((open) => !open)}
            >
              {isMobileMenuOpen ? <X size={20} aria-hidden /> : <Menu size={20} aria-hidden />}
            </button>
          </div>
        </div>

        <div
          className={`navbar-static__dropdown-surface${openDropdown ? ' is-open' : ''}`}
          style={dropdownSurfaceStyle}
          onMouseEnter={clearDropdownTimers}
          onMouseLeave={() => scheduleCloseDropdown()}
          onFocusCapture={clearDropdownTimers}
          onBlurCapture={(e) => {
            const next = e.relatedTarget
            if (next instanceof Node && rootRef.current?.contains(next)) return
            scheduleCloseDropdown(0)
          }}
        >
          <div
            ref={dropdownPanelRef}
            className="navbar-static__dropdown-inner"
            role="menu"
            aria-label={dropdownAriaConfig ? dropdownAriaConfig.label : undefined}
            aria-orientation="vertical"
            onKeyDown={onDropdownPanelKeyDown}
          >
            <div className="navbar-static__dropdown-stack">
              {dropdownConfigs.map((config) => {
                const rootProps = getNavLinkProps(config.rootTo)
                const isActive = activeDropdownId === config.id && leavingDropdown !== config.id
                const isLeaving = leavingDropdown === config.id
                const viewClassName = [
                  'navbar-static__dropdown-view',
                  isActive ? 'is-active' : '',
                  isLeaving ? 'is-leaving' : '',
                ]
                  .filter(Boolean)
                  .join(' ')

                return (
                  <div
                    key={config.id}
                    id={`navbar-dropdown-${config.id}`}
                    className={viewClassName}
                    data-dropdown-view={config.id}
                    aria-hidden={!isActive}
                  >
                    {config.sections.map((section) => (
                      <section className="navbar-static__dropdown-section" key={section.heading}>
                        <h3 className="navbar-static__dropdown-title">{section.heading}</h3>
                        <div className="navbar-static__dropdown-grid">
                          {section.items.map((item) => {
                            const itemProps = getNavLinkProps(item.to)
                            return (
                              <a
                                key={item.title}
                                className="navbar-static__dropdown-card"
                                role="menuitem"
                                href={itemProps.href}
                                onClick={itemProps.onClick}
                              >
                                <p className="navbar-static__dropdown-card-title">{item.title}</p>
                                <p className="navbar-static__dropdown-card-description">{item.description}</p>
                              </a>
                            )
                          })}
                        </div>
                      </section>
                    ))}
                    <a
                      className="navbar-static__dropdown-all"
                      role="menuitem"
                      href={rootProps.href}
                      onClick={rootProps.onClick}
                    >
                      {config.allLabel}
                    </a>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      <div className={`navbar-static__mobile-menu${isMobileMenuOpen ? ' is-open' : ''}`}>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileProductsOpen}
          onClick={() => {
            setIsMobileProductsOpen((open) => !open)
            setIsMobileSolutionsOpen(false)
          }}
        >
          <span>Products</span>
          <ChevronDown size={16} className={`navbar-static__chevron${isMobileProductsOpen ? ' is-open' : ''}`} aria-hidden />
        </button>
        <div className={`navbar-static__mobile-submenu${isMobileProductsOpen ? ' is-open' : ''}`}>
          {productSections.map((section) => (
            <section key={section.heading} className="navbar-static__mobile-section">
              <h3 className="navbar-static__mobile-section-title">{section.heading}</h3>
              {section.items.map((item) => {
                const itemProps = getNavLinkProps(item.to)
                return (
                  <a
                    key={item.title}
                    className="navbar-static__mobile-subitem"
                    href={itemProps.href}
                    onClick={itemProps.onClick}
                  >
                    <span>{item.title}</span>
                    <small>{item.description}</small>
                  </a>
                )
              })}
            </section>
          ))}
          <a className="navbar-static__mobile-subitem" href={productsRootProps.href} onClick={productsRootProps.onClick}>
            <span>View all products</span>
            <small>Explore every wallet, signing, and security capability</small>
          </a>
        </div>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileSolutionsOpen}
          onClick={() => {
            setIsMobileSolutionsOpen((open) => !open)
            setIsMobileProductsOpen(false)
          }}
        >
          <span>Solutions</span>
          <ChevronDown size={16} className={`navbar-static__chevron${isMobileSolutionsOpen ? ' is-open' : ''}`} aria-hidden />
        </button>
        <div className={`navbar-static__mobile-submenu${isMobileSolutionsOpen ? ' is-open' : ''}`}>
          {solutionSections.map((section) => (
            <section key={section.heading} className="navbar-static__mobile-section">
              <h3 className="navbar-static__mobile-section-title">{section.heading}</h3>
              {section.items.map((item) => {
                const itemProps = getNavLinkProps(item.to)
                return (
                  <a
                    key={item.title}
                    className="navbar-static__mobile-subitem"
                    href={itemProps.href}
                    onClick={itemProps.onClick}
                  >
                    <span>{item.title}</span>
                    <small>{item.description}</small>
                  </a>
                )
              })}
            </section>
          ))}
          <a className="navbar-static__mobile-subitem" href={solutionsRootProps.href} onClick={solutionsRootProps.onClick}>
            <span>View all solutions</span>
            <small>Explore every use case and team-oriented path</small>
          </a>
        </div>
        <a className="navbar-static__mobile-link" href={docsProps.href} onClick={docsProps.onClick}>Documentation</a>
        <a className="navbar-static__mobile-link" href={pricingProps.href} onClick={pricingProps.onClick}>Pricing</a>
        <a className="navbar-static__mobile-link" href={companyProps.href} onClick={companyProps.onClick}>Company</a>
        <div className="navbar-static__mobile-cta-row">
          <a
            className="navbar-static__pill navbar-static__pill--ghost"
            href="https://github.com/web3-authn/tatchi"
            target="_blank"
            rel="noopener noreferrer"
            onClick={closeMenus}
          >
            GitHub
          </a>
          <a
            className="navbar-static__pill navbar-static__pill--ghost"
            href={contactSalesProps.href}
            onClick={contactSalesProps.onClick}
          >
            Contact Sales
          </a>
          <a
            className="navbar-static__pill navbar-static__pill--solid"
            href={getStartedProps.href}
            onClick={getStartedProps.onClick}
          >
            Get Started
          </a>
        </div>
      </div>
    </nav>
  )
}

export default NavbarStatic

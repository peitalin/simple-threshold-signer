# Frontpage Professionalization Plan

Date updated: February 15, 2026

## Goal

Professionalize the public docs homepage and top-level marketing paths so a new visitor can quickly understand:

1. What Tatchi is.
2. Who it is for.
3. Why it is credible.
4. What to do next.

## Current State (Rebased)

### Already Completed

- [x] Top-level IA is implemented in custom homepage navbar:
  - `Products`, `Solutions`, `Documentation`, `Pricing`, `Company`
  - CTA actions: `GitHub`, `Contact Sales`, `Get Started`
  - File: `examples/tatchi-docs/src/components/Navbar/NavbarStatic.tsx`
- [x] Mobile menu includes the same IA and CTA structure.
- [x] Top-level pages exist:
  - `examples/tatchi-docs/src/products/index.md`
  - `examples/tatchi-docs/src/solutions/index.md`
  - `examples/tatchi-docs/src/pricing/index.md`
  - `examples/tatchi-docs/src/company/index.md`
- [x] Dedicated sales contact route exists:
  - `examples/tatchi-docs/src/contact/index.md`
- [x] Hero copy now uses consistent `Tatchi` naming and outcome-first messaging.
  - File: `examples/tatchi-docs/src/components/HomeHero.tsx`
- [x] Homepage includes trust/products/solutions/security/final CTA sections.
  - File: `examples/tatchi-docs/src/pages/HomePage.tsx`
- [x] Default VitePress nav includes top-level routes for non-home pages.
  - File: `examples/tatchi-docs/src/.vitepress/config.ts`
- [x] Sales/contact CTAs no longer point to personal-profile links.
  - Files:
    - `examples/tatchi-docs/src/components/Navbar/NavbarStatic.tsx`
    - `examples/tatchi-docs/src/components/Footer.tsx`
    - `examples/tatchi-docs/src/pricing/index.md`

### Gaps Still Open

- [ ] Proof and credibility assets are still thin.
  - No customer logos/metrics/case snapshots on homepage.
- [ ] Social proof content is generic and should be replaced with real customer/evidence assets.
- [ ] Contact route currently uses GitHub issue intake and may need a CRM/form workflow for production GTM.

## Execution Backlog

### Phase A: Messaging + Conversion Plumbing (Immediate)

- [x] Standardize public naming to `Tatchi` across homepage marketing copy.
- [x] Rewrite hero to outcome-first positioning with:
  - one clear headline,
  - one value subhead,
  - one proof sentence,
  - two CTAs (`Get Started`, `Contact Sales`).
- [x] Add a dedicated `/contact/` page and route all `Contact Sales`/`Talk to Sales` links there.
- [x] Ensure footer includes the same conversion path and avoids personal-profile links.

### Phase B: Homepage Structure Rebuild

- [x] Add and integrate new homepage sections in this order:
  1. Hero
  2. Trust strip
  3. Product modules
  4. Solution modules
  5. Security proof strip
  6. Developer quickstart (existing install block)
  7. Final CTA
  8. Footer
- [x] Replace ad-hoc section styling with reusable section/card/CTA patterns.

### Phase C: Content Credibility

- [ ] Add at least one trust asset per category:
  - ecosystem/customer logo row,
  - adoption metric or usage stat,
  - short case snapshot.
- [x] Add explicit security credibility links:
  - `/docs/concepts/security-model`
  - `/docs/concepts/threshold-signing`
  - `/docs/concepts/secureconfirm-webauthn`

### Phase D: QA and Readiness

- [ ] Verify responsive quality at mobile/tablet/desktop breakpoints.
- [ ] Verify keyboard/focus-visible interactions for all nav/CTA elements.
- [x] Verify homepage and top-level routes resolve correctly (build routes generated successfully).
- [ ] Capture before/after screenshots for sign-off.

## Success Criteria

- [ ] A first-time visitor can explain the value proposition within 10 seconds.
- [ ] Homepage supports both self-serve developer onboarding and sales-led evaluation.
- [ ] Conversion actions are clear and repeated (`Get Started`, `Contact Sales`, `GitHub`).
- [ ] Messaging is outcome-first while linking to technical depth one click away.

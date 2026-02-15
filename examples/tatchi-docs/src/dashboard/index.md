---
layout: home
title: Dashboard Mock
---

<div class="dashboard-page">
  <div class="dashboard-shell">
    <header class="dashboard-topbar">
      <div class="dashboard-brand-row">
        <div class="dashboard-logo" aria-hidden="true"></div>
        <div class="dashboard-apps">
          <span>Game2</span>
          <span>/</span>
          <strong>Game1</strong>
          <span class="dashboard-env">Dev</span>
        </div>
      </div>
      <div class="dashboard-avatar" aria-label="Current user">P</div>
    </header>

    <div class="dashboard-body">
      <aside class="dashboard-sidebar" aria-label="Dashboard navigation">
        <nav class="dashboard-nav-group">
          <h2 class="dashboard-nav-title">Home</h2>
        </nav>

        <nav class="dashboard-nav-group">
          <h2 class="dashboard-nav-title">Configuration</h2>
          <a class="dashboard-link" href="#">App settings</a>
          <a class="dashboard-link" href="#">UI components</a>
          <a class="dashboard-link" href="#">Webhooks</a>
          <a class="dashboard-link" href="#">Integrations</a>
        </nav>

        <nav class="dashboard-nav-group">
          <h2 class="dashboard-nav-title">Wallet infrastructure</h2>
          <a class="dashboard-link is-active" href="#">Wallets</a>
          <a class="dashboard-link" href="#">Authorization</a>
          <a class="dashboard-link" href="#">Policies</a>
          <a class="dashboard-link" href="#">Smart wallets</a>
          <a class="dashboard-link" href="#">Gas sponsorship</a>
        </nav>

        <nav class="dashboard-nav-group">
          <h2 class="dashboard-nav-title">User management</h2>
          <a class="dashboard-link" href="#">Users</a>
          <a class="dashboard-link" href="#">Authentication</a>
          <a class="dashboard-link" href="#">Account funding</a>
          <a class="dashboard-link" href="#">Global wallet</a>
        </nav>
      </aside>

      <main class="dashboard-main">
        <section class="dashboard-panel" aria-label="Wallets overview">
          <div class="dashboard-panel-head">
            <h1>Wallets</h1>
            <a class="dashboard-pill-button" href="#">New wallet</a>
          </div>

          <div class="dashboard-tabs" role="tablist" aria-label="Wallet tabs">
            <button class="dashboard-tab is-active" type="button">Wallets</button>
            <button class="dashboard-tab" type="button">Outgoing transactions</button>
            <button class="dashboard-tab" type="button">Advanced</button>
          </div>

          <div class="dashboard-metrics">
            <article class="dashboard-stat">
              <h3>Total assets</h3>
              <p>$0</p>
            </article>
            <article class="dashboard-stat">
              <h3>Wallets</h3>
              <p>0</p>
            </article>
            <article class="dashboard-stat">
              <h3>Funded wallets</h3>
              <p>0</p>
            </article>
          </div>

          <div class="dashboard-filter-row">
            <div class="dashboard-input">Search by wallet address or ID</div>
            <div class="dashboard-select">Key quorum...</div>
            <div class="dashboard-select">Policy...</div>
          </div>

          <div class="dashboard-table" role="table" aria-label="Wallet list">
            <div class="dashboard-table-header" role="row">
              <div role="columnheader">Wallet</div>
              <div role="columnheader">Chain type</div>
              <div role="columnheader">Owner</div>
              <div role="columnheader">Policy</div>
              <div role="columnheader">Balance</div>
            </div>
            <div class="dashboard-table-empty" role="row">
              <div>
                <div class="dashboard-empty-mark" aria-hidden="true"></div>
                <strong>No results found</strong>
                <p>We could not find any wallets.</p>
              </div>
            </div>
          </div>
        </section>

        <section class="dashboard-panel dashboard-panel--subtle" aria-label="Authentication mock">
          <div class="dashboard-panel-head">
            <h2>User authentication</h2>
          </div>

          <div class="dashboard-subtabs" role="tablist" aria-label="Authentication tabs">
            <div class="dashboard-subtab">Basics</div>
            <div class="dashboard-subtab">Socials</div>
            <div class="dashboard-subtab is-active">MFA</div>
            <div class="dashboard-subtab">Advanced</div>
          </div>

          <article class="dashboard-setting">
            <div class="dashboard-switch-row">
              <h3>Enable MFA for transactions</h3>
              <div class="dashboard-switch" aria-hidden="true"></div>
            </div>
            <p>
              Users who enable MFA must verify with a second factor when signing high-risk transactions.
              Cache duration is configurable per environment.
            </p>
            <div class="dashboard-mfa-list">
              <div class="dashboard-mfa-item"><span>Authenticator app</span><span>Disabled</span></div>
              <div class="dashboard-mfa-item"><span>Passkey</span><span>Disabled</span></div>
              <div class="dashboard-mfa-item"><span>SMS (US and Canada)</span><span>Disabled</span></div>
            </div>
          </article>

          <p class="dashboard-requirements-link">
            Feature planning document lives in the repo at <code>docs/dashboard-requirements.md</code>.
          </p>
        </section>
      </main>
    </div>
  </div>
</div>

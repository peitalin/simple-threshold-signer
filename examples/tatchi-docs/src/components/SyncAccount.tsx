import React from 'react'
import { useTatchi, PROFILE_MENU_ITEM_IDS, SyncAccountPhase, SyncAccountStatus, type SyncAccountSSEEvent } from '@tatchi-xyz/sdk/react'
import { toast } from 'sonner'
import { friendlyWebAuthnMessage } from '../utils/strings'
import { LoadingButton } from './LoadingButton';
import { GlassBorder } from './GlassBorder'
import { BrowserWithQR } from './icons/BrowserWithQR'
import { IPhoneQRScanner } from './icons/IPhoneQRScanner'
import { useProfileMenuControl } from '../contexts/ProfileMenuControl'
import './SyncAccount.css'
import { SetupEmailRecovery } from './SetupEmailRecovery';

export function SyncAccount() {
  const {
    loginState,
    logout,
    refreshLoginState,
    accountInputState: { targetAccountId },
    tatchi,
  } = useTatchi()
  const [busy, setBusy] = React.useState(false)
  const { requestHighlight: requestProfileHighlight } = useProfileMenuControl()

  const onSync = async () => {
    setBusy(true)
    try {
      if (!targetAccountId) {
        toast.error('Enter an account ID first (Register/Login tab).')
        return
      }

      const toastId = 'sync-account'
      toast.loading(`Syncing ${targetAccountId}…`, { id: toastId })

      // Best-effort: ensure we are logged out before starting recovery flows.
      try { await logout(); } catch {}

      const result = await tatchi.syncAccount({
        accountId: targetAccountId,
        options: {
          onEvent: async (event: SyncAccountSSEEvent) => {
            try {
              if (event.phase === SyncAccountPhase.STEP_5_SYNC_ACCOUNT_COMPLETE && event.status === SyncAccountStatus.SUCCESS) {
                await refreshLoginState(targetAccountId)
              }
            } catch {}
          },
          onError: (error: Error) => {
            console.error('Sync error:', error)
          },
        },
      })

      if (result?.success) {
        toast.success(`Account ${targetAccountId} synced successfully!`, { id: toastId })
      } else {
        throw new Error(result?.error || 'syncAccount failed')
      }
    } catch (err) {
      // Best-effort UX; show friendly error if anything goes wrong
      toast.error(friendlyWebAuthnMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const onLinkDevice = React.useCallback(() => {
    if (!loginState.isLoggedIn) {
      toast.error('Log in to link another device')
      return
    }
    requestProfileHighlight({
      id: PROFILE_MENU_ITEM_IDS.SCAN_LINK_DEVICE,
      focus: true,
    })
  }, [loginState.isLoggedIn, requestProfileHighlight])

  return (
    <GlassBorder style={{ maxWidth: 480, marginTop: '1rem' }}>
      <div className="action-section">
        <div className="demo-page-header">
          <h2 className="demo-title">Account Recovery</h2>
        </div>

        <SetupEmailRecovery />

        <div style={{
          marginTop: '2rem',
          paddingTop: '2rem',
          borderTop: '1px solid var(--fe-border)'
        }}>
          <h2 className="demo-title">Recover Passkey Account</h2>
          <div className="action-text">
            Sync accounts on any device where your passkeys are synced,
            such as iCloud Keychain or Google Password Manager.
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <LoadingButton
              onClick={onSync}
              loading={busy}
              loadingText="Syncing..."
              variant="primary"
              size="medium"
              style={{ width: 200 }}
            >
              Start Sync
            </LoadingButton>
          </div>
        </div>

        <div style={{
          marginTop: '2rem',
          paddingTop: '2rem',
          borderTop: '1px solid var(--fe-border)'
        }}>
          <h2 className="demo-title">Device Linking</h2>
          <div className="action-text">
            Use QR codes to scan and link a new device to your account.
            Backup your wallet on multiple devices without remembering keys, or passphrases.
          </div>
          <div className="account-recovery-link-device-button">
            <LoadingButton
              onClick={onLinkDevice}
              variant="secondary"
              size="medium"
              style={{ width: 200 }}
            >
              Link Device
            </LoadingButton>
          </div>
          <div
            aria-label="Illustration: iPhone scanning browser QR code"
            style={{
              marginTop: '2rem',
              marginBottom: '2rem',
              width: '100%',
              height: 230,
              position: 'relative',
              borderRadius: 12,
              overflow: 'visible',
            }}
          >
            <BrowserWithQR width="100%" height="100%" />
            <IPhoneQRScanner
              width={110}
              style={{
                position: 'absolute',
                right: 16,
                bottom: -8,
                transform: 'rotate(-6deg)',
                filter: 'drop-shadow(0 6px 14px rgba(0,0,0,0.28))',
              }}
            />
          </div>
        </div>
      </div>
    </GlassBorder>
  )
}

export default SyncAccount

import React, { useState, useEffect } from 'react';
import { useTatchi } from '../../context';
import './LinkedDevicesModal.css';
import { useTheme, Theme } from '../theme';
import type { AccessKeyList } from '@/core/near/NearClient';
import { IndexedDBManager } from '@/core/IndexedDBManager';
import { toAccountId } from '../../../core/types/accountIds';

interface LinkedDevicesModalProps {
  nearAccountId: string;
  isOpen: boolean;
  onClose: () => void;
}

type RelayAuthenticatorRow = {
  credentialIdB64u: string;
  deviceNumber?: number;
  publicKey?: string;
  createdAtMs?: number;
  updatedAtMs?: number;
};

type AccessKeyKind = 'threshold' | 'local' | 'backup';

export const LinkedDevicesModal: React.FC<LinkedDevicesModalProps> = ({
  nearAccountId,
  isOpen,
  onClose
}) => {
  const { tatchi, loginState, viewAccessKeyList } = useTatchi();
  const { theme } = useTheme();
  const pageSize = 3;
  // Authenticators list: credentialId + registered timestamp + device number
  const [authRows, setAuthRows] = useState<Array<{
    credentialId: string;
    registered: string;
    deviceNumber: number;
    nearPublicKey: string | null;
    keyKind: AccessKeyKind;
  }>>([{ credentialId: 'placeholder', registered: '', deviceNumber: 0, nearPublicKey: null, keyKind: 'backup' }]);
  const [page, setPage] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [accessKeyList, setAccessKeyList] = useState<AccessKeyList | null>(null);
  const [tooltipVisible, setTooltipVisible] = useState<number | null>(null);
  const [copiedKeys, setCopiedKeys] = useState<Set<number>>(new Set());
  const [currentDeviceNumber, setCurrentDeviceNumber] = useState<number | null>(null);
  const [deletingKeyPublicKey, setDeletingKeyPublicKey] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const formatDateTime = (iso: string) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  };

  useEffect(() => {
    if (isOpen) {
      setPage(0);
      loadAuthenticators();
    }
  }, [isOpen, nearAccountId]);

  useEffect(() => {
    if (!isOpen) return;
    setPage(0);
  }, [isOpen, authRows.length]);

  // Close on ESC press while modal is open
  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Esc') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  const loadAuthenticators = async () => {
    if (!tatchi) return;

    setIsLoading(true);
    setError(null);
    setDeleteError(null);

    try {
      // Resolve current device number for highlighting + local key lookups
      let currentDeviceNumberFromState: number | null = null;
      try {
        const { login } = await tatchi.getLoginSession(nearAccountId);
        const dn = (login as any)?.userData?.deviceNumber;
        currentDeviceNumberFromState = (typeof dn === 'number' && Number.isFinite(dn)) ? Math.floor(dn) : null;
      } catch {
        currentDeviceNumberFromState = null;
      }
      setCurrentDeviceNumber(currentDeviceNumberFromState);

      const keys = await viewAccessKeyList(nearAccountId);
      setAccessKeyList(keys);

      const keyMetaByPublicKey = new Map<string, { kind: AccessKeyKind; deviceNumber?: number; createdAtMs?: number; updatedAtMs?: number }>();

      // Best-effort: fetch device metadata from relay-private WebAuthn stores (auth-protected).
      // This annotates access keys with device numbers and registration timestamps.
      const relayMetaByPublicKey = new Map<string, RelayAuthenticatorRow>();
      try {
        const relayerUrl = String((tatchi as any)?.configs?.relayer?.url || '').trim().replace(/\/$/, '');
        if (relayerUrl) {
          // Prefer the dedicated key metadata endpoint when available.
          try {
            const resp = await fetch(`${relayerUrl}/near/public-keys`, { method: 'GET', credentials: 'include' });
            const json = await resp.json().catch(() => ({} as any));
            const list = resp.ok && json?.ok === true && Array.isArray(json?.keys) ? json.keys as any[] : [];
            for (const row of list) {
              const pk = typeof row?.publicKey === 'string' ? row.publicKey.trim() : '';
              const kind = typeof row?.kind === 'string' ? row.kind.trim() : '';
              if (!pk || !kind) continue;
              if (kind !== 'threshold' && kind !== 'local' && kind !== 'backup') continue;
              const deviceNumber = typeof row?.deviceNumber === 'number' && Number.isFinite(row.deviceNumber) ? Math.floor(row.deviceNumber) : undefined;
              const createdAtMs = typeof row?.createdAtMs === 'number' && Number.isFinite(row.createdAtMs) ? Math.floor(row.createdAtMs) : undefined;
              const updatedAtMs = typeof row?.updatedAtMs === 'number' && Number.isFinite(row.updatedAtMs) ? Math.floor(row.updatedAtMs) : undefined;
              keyMetaByPublicKey.set(pk, { kind: kind as AccessKeyKind, ...(deviceNumber ? { deviceNumber } : {}), ...(createdAtMs ? { createdAtMs } : {}), ...(updatedAtMs ? { updatedAtMs } : {}) });
            }
          } catch {
            // ignore
          }

          const rpIdOverride = String((tatchi as any)?.configs?.rpIdOverride || '').trim();
          const rpId = rpIdOverride || (typeof window !== 'undefined' ? String(window.location.hostname || '').trim() : '');
          const url = `${relayerUrl}/webauthn/authenticators${rpId ? `?rpId=${encodeURIComponent(rpId)}` : ''}`;
          const resp = await fetch(url, { method: 'GET', credentials: 'include' });
          const json = await resp.json().catch(() => ({} as any));
          const list: RelayAuthenticatorRow[] =
            resp.ok && json?.ok === true && Array.isArray(json?.authenticators)
              ? json.authenticators
              : [];
          for (const row of list) {
            const pk = typeof row?.publicKey === 'string' ? row.publicKey.trim() : '';
            if (!pk) continue;
            relayMetaByPublicKey.set(pk, row);
          }
        }
      } catch {
        // Ignore relay metadata failures; fallback is pure on-chain access key listing.
      }

      const currentKey = loginState?.nearPublicKey || null;
      const localKeyMaterial = currentDeviceNumberFromState != null
        ? await IndexedDBManager.getNearLocalKeyMaterialV2First(toAccountId(nearAccountId), currentDeviceNumberFromState).catch(() => null)
        : null;
      const thresholdKeyMaterial = currentDeviceNumberFromState != null
        ? await IndexedDBManager.getNearThresholdKeyMaterialV2First(toAccountId(nearAccountId), currentDeviceNumberFromState).catch(() => null)
        : null;

      const nextDeviceNumber = (() => {
        let next = 1;
        return () => {
          while (currentDeviceNumberFromState != null && next === currentDeviceNumberFromState) next++;
          return next++;
        };
      })();

      const rows: Array<{
        credentialId: string;
        registered: string;
        deviceNumber: number;
        nearPublicKey: string | null;
        keyKind: AccessKeyKind;
      }> = [];
      const items = Array.isArray((keys as any)?.keys) ? (keys as any).keys as Array<{ public_key?: unknown }> : [];
      for (const item of items) {
        const publicKey = typeof item?.public_key === 'string' ? item.public_key : null;
        const isCurrent = !!publicKey && !!currentKey && publicKey === currentKey;
        const keyMeta = publicKey ? keyMetaByPublicKey.get(publicKey) : undefined;
        const relayMeta = publicKey ? relayMetaByPublicKey.get(publicKey) : undefined;
        const metaDeviceNumber = keyMeta && typeof keyMeta.deviceNumber === 'number' && Number.isFinite(keyMeta.deviceNumber)
          ? Math.floor(keyMeta.deviceNumber)
          : null;
        const relayDeviceNumber = relayMeta && typeof relayMeta.deviceNumber === 'number' && Number.isFinite(relayMeta.deviceNumber)
          ? Math.floor(relayMeta.deviceNumber)
          : null;
        const deviceNumber =
          isCurrent && currentDeviceNumberFromState != null
            ? currentDeviceNumberFromState
            : (metaDeviceNumber && metaDeviceNumber >= 1 ? metaDeviceNumber : (relayDeviceNumber && relayDeviceNumber >= 1 ? relayDeviceNumber : nextDeviceNumber()));

        const keyKind: AccessKeyKind = (() => {
          if (keyMeta?.kind) return keyMeta.kind;
          if (publicKey && relayMetaByPublicKey.has(publicKey)) return 'threshold';
          if (publicKey && thresholdKeyMaterial?.publicKey && publicKey === thresholdKeyMaterial.publicKey) return 'threshold';
          if (publicKey && localKeyMaterial?.publicKey && publicKey === localKeyMaterial.publicKey) return 'local';
          return 'backup';
        })();

        const registered = (() => {
          const createdAtMsFromMeta = keyMeta && typeof keyMeta.createdAtMs === 'number' ? keyMeta.createdAtMs : null;
          if (createdAtMsFromMeta && Number.isFinite(createdAtMsFromMeta) && createdAtMsFromMeta > 0) {
            try { return new Date(createdAtMsFromMeta).toISOString(); } catch { return ''; }
          }
          const createdAtMs = relayMeta && typeof relayMeta.createdAtMs === 'number' ? relayMeta.createdAtMs : null;
          if (createdAtMs && Number.isFinite(createdAtMs) && createdAtMs > 0) {
            try { return new Date(createdAtMs).toISOString(); } catch { return ''; }
          }
          if (keyKind === 'local' && localKeyMaterial?.timestamp && Number.isFinite(localKeyMaterial.timestamp)) {
            try { return new Date(localKeyMaterial.timestamp).toISOString(); } catch { return ''; }
          }
          return '';
        })();
        rows.push({
          credentialId: publicKey || `access-key-${deviceNumber}`,
          registered,
          deviceNumber,
          nearPublicKey: publicKey,
          keyKind,
        });
      }
      setAuthRows(rows);
    } catch (err: any) {
      setError(err.message || 'Failed to load linked devices or access keys');
      setAccessKeyList(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteKey = async (publicKey: string) => {
    if (!tatchi || !publicKey) return;
    if (!nearAccountId) return;

    setDeletingKeyPublicKey(publicKey);
    setDeleteError(null);

    try {
      await tatchi.deleteDeviceKey(nearAccountId, publicKey, {
        signerMode: { mode: 'threshold-signer', behavior: 'fallback' },
      });
      await loadAuthenticators();
    } catch (err: any) {
      setDeleteError(err.message || 'Failed to delete access key');
    } finally {
      setDeletingKeyPublicKey(null);
    }
  };

  const copyToClipboard = async (text: string, keyIndex: number) => {
    try {
      await navigator.clipboard.writeText(text);

      // Fire custom event for copy action
      const copyEvent = new CustomEvent('accessKeyCopied', {
        detail: {
          publicKey: text,
          keyIndex: keyIndex,
          timestamp: Date.now()
        }
      });
      window.dispatchEvent(copyEvent);

      // Show brief tooltip feedback
      setTooltipVisible(keyIndex);
      setTimeout(() => setTooltipVisible(null), 2000);

      // Set copied state for status badge
      setCopiedKeys(prev => new Set(prev).add(keyIndex));
      setTimeout(() => {
        setCopiedKeys(prev => {
          const newSet = new Set(prev);
          newSet.delete(keyIndex);
          return newSet;
        });
      }, 3000);
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  if (!isOpen) return null;

  // Prevent any events from bubbling up to parent components
  const handleBackdropClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onClose();
  };

  const handleModalContentClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    // Don't call onClose here - we want to keep the modal open
  };

  return (
    <Theme theme={theme}>
      <div className={`w3a-access-keys-modal-backdrop theme-${theme}`}
        onClick={handleBackdropClick}
        onMouseDown={(e) => e.stopPropagation()}
        onMouseUp={(e) => e.stopPropagation()}
      >
        <div className="w3a-access-keys-modal-content"
          onClick={handleModalContentClick}
          onMouseDown={(e) => e.stopPropagation()}
          onMouseUp={(e) => e.stopPropagation()}
        >
          <div className="w3a-access-keys-modal-header">
            <h2 className="w3a-access-keys-modal-title">Linked Devices</h2>
          </div>
          <button className="w3a-access-keys-modal-close"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onClose();
            }}
          >
            ✕
          </button>

          {error && (
            <div className="w3a-access-keys-error">
              <p>{error}</p>
              <button onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                loadAuthenticators();
              }} className="w3a-btn w3a-btn-primary">
                Try Again
              </button>
            </div>
          )}

          {!isLoading && !error && authRows.filter(r => r.credentialId !== 'placeholder').length === 0 && (
            <div className="w3a-access-keys-empty">
              <p>No linked devices found.</p>
            </div>
          )}

          {!error && authRows.filter(r => r.credentialId !== 'placeholder').length > 0 && (
            <div className="w3a-keys-list">
              {(() => {
                const rows = authRows.filter(r => r.credentialId !== 'placeholder');
                const current = (currentDeviceNumber != null)
                  ? rows.find(r => r.deviceNumber === currentDeviceNumber)
                  : null;
                const othersAll = (currentDeviceNumber != null)
                  ? rows.filter(r => r.deviceNumber !== currentDeviceNumber)
                  : rows;

                const totalOthers = othersAll.length;
                const totalPages = Math.max(1, Math.ceil(totalOthers / pageSize));
                const pageSafe = Math.min(page, Math.max(0, totalPages - 1));
                const startIndex = pageSafe * pageSize;
                const endIndex = Math.min(totalOthers, startIndex + pageSize);
                const others = othersAll.slice(startIndex, endIndex);

                const items: React.ReactNode[] = [];

                if (current) {
                  const index = 0;
                  const currentKey = current.nearPublicKey || loginState?.nearPublicKey || null;
                  const isCurrentKey = !!currentKey && loginState?.nearPublicKey === currentKey;
                  const canDelete = !!accessKeyList && accessKeyList.keys.length > 1;
                  const isDeletingThisKey = !!currentKey && deletingKeyPublicKey === currentKey;
                  items.push(
                    <div key={`current-${current.deviceNumber}`} className="w3a-key-item">
                      <div className="w3a-key-content">
                        <div className="w3a-key-details">
                          <div className="w3a-key-header">
                            <div className="mono w3a-device-row">
                              <span className="w3a-device-badge">Device {current.deviceNumber}</span>
                              <span className="w3a-current-device-text">(current device)</span>
                            </div>
                          </div>
                          <div className="mono w3a-key-kind">
                            Type: <span className={`w3a-key-kind-badge w3a-key-kind-${current.keyKind}`}>{current.keyKind}</span>
                          </div>
                          <div className="mono w3a-registered">Registered: {formatDateTime(current.registered)}</div>
                          {currentKey && (
                            <div
                              className="mono w3a-copyable-key w3a-access-key-current"
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(currentKey, index);
                              }}
                              onMouseEnter={() => setTooltipVisible(index)}
                              onMouseLeave={() => setTooltipVisible(null)}
                              title="Click to copy"
                            >
                              Access Key: {currentKey}
                              {tooltipVisible === index && (
                                <div className="w3a-copy-tooltip">Click to copy</div>
                              )}
                            </div>
                          )}
                        </div>
                        {currentKey && (
                          <div className="w3a-key-status">
                            <button
                              className={`w3a-btn ${isCurrentKey ? 'w3a-btn-primary' : 'w3a-btn-danger'}`}
                              style={{ width: '64px' }}
                              disabled={!canDelete || isDeletingThisKey}
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                if (canDelete && !isDeletingThisKey) {
                                  void handleDeleteKey(currentKey);
                                }
                              }}
                            >
                              {isDeletingThisKey ? (
                                <span className="w3a-spinner"/>
                              ) : (
                                'Delete'
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }

                others.forEach((item, i) => {
                  const globalIndex = startIndex + i;
                  const canDelete = !!accessKeyList && accessKeyList.keys.length > 1;
                  const isDeletingThisKey = !!item.nearPublicKey && deletingKeyPublicKey === item.nearPublicKey;
                  items.push(
                    <div key={`other-${item.deviceNumber}-${i}`} className="w3a-key-item">
                      <div className="w3a-key-content">
                        <div className="w3a-key-details">
                          <div className="w3a-key-header">
                            <div className="mono w3a-device-row">
                              <span className="w3a-device-badge">Device {item.deviceNumber}</span>
                            </div>
                          </div>
                          <div className="mono w3a-key-kind">
                            Type: <span className={`w3a-key-kind-badge w3a-key-kind-${item.keyKind}`}>{item.keyKind}</span>
                          </div>
                          <div className="mono w3a-registered">Registered: {formatDateTime(item.registered)}</div>
                          {item.nearPublicKey && (
                            <div
                              className="mono w3a-copyable-key"
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(item.nearPublicKey!, 10 + globalIndex);
                              }}
                              onMouseEnter={() => setTooltipVisible(10 + globalIndex)}
                              onMouseLeave={() => setTooltipVisible(null)}
                              title="Click to copy"
                            >
                              Access Key: {item.nearPublicKey}
                              {tooltipVisible === 10 + globalIndex && (
                                <div className="w3a-copy-tooltip">Click to copy</div>
                              )}
                            </div>
                          )}
                        </div>
                        {item.nearPublicKey && (
                          <div className="w3a-key-status">
                            <button
                              className="w3a-btn w3a-btn-danger"
                              style={{ width: '64px' }}
                              disabled={!canDelete || isDeletingThisKey}
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                if (canDelete && !isDeletingThisKey) {
                                  void handleDeleteKey(item.nearPublicKey!);
                                }
                              }}
                            >
                              {isDeletingThisKey ? (
                                <span className="w3a-spinner"/>
                              ) : (
                                'Delete'
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                });

                return items;
              })()}
            </div>
          )}

          {!error && authRows.filter(r => r.credentialId !== 'placeholder').length > 0 && (
            (() => {
              const rows = authRows.filter(r => r.credentialId !== 'placeholder');
              const current = (currentDeviceNumber != null)
                ? rows.find(r => r.deviceNumber === currentDeviceNumber)
                : null;
              const othersAll = (currentDeviceNumber != null && current)
                ? rows.filter(r => r.deviceNumber !== currentDeviceNumber)
                : rows;
              const totalOthers = othersAll.length;
              const totalPages = Math.max(1, Math.ceil(totalOthers / pageSize));
              const pageSafe = Math.min(page, Math.max(0, totalPages - 1));
              const startIndex = pageSafe * pageSize;
              const endIndex = Math.min(totalOthers, startIndex + pageSize);
              if (totalPages <= 1) return null;

              return (
                <div className="w3a-pagination" onClick={(e) => e.stopPropagation()}>
                  <button
                    type="button"
                    className="w3a-btn w3a-btn-primary"
                    disabled={pageSafe <= 0}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setPage((p) => Math.max(0, p - 1));
                    }}
                  >
                    Prev
                  </button>
                  <div className="w3a-pagination-info">
                    {startIndex + 1}-{endIndex} of {totalOthers} (page {pageSafe + 1}/{totalPages})
                  </div>
                  <button
                    type="button"
                    className="w3a-btn w3a-btn-primary"
                    disabled={pageSafe >= totalPages - 1}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setPage((p) => Math.min(totalPages - 1, p + 1));
                    }}
                  >
                    Next
                  </button>
                </div>
              );
            })()
          )}

          {deleteError && (
            <div className="w3a-access-keys-error">
              <p>{deleteError}</p>
            </div>
          )}
        </div>
      </div>
    </Theme>
  );
};

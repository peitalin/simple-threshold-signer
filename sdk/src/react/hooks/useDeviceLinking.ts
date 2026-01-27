import { useRef, useCallback } from 'react';
import { useTatchi } from '../context';
import {
  DeviceLinkingPhase,
  DeviceLinkingStatus,
  type DeviceLinkingQRData,
  type LinkDeviceResult,
  type DeviceLinkingSSEEvent
} from '@/index';
import { QRScanMode } from '@/react/hooks/useQRCamera';

/**
 * Device Linking Hook
 *
 * Provides device linking functionality with QR code scanning and transaction management.
 *
 * **Important:** This hook must be used inside a TatchiPasskey context.
 * Wrap your app with TatchiPasskeyProvider or ensure TatchiPasskey is available in context via useTatchi.
 *
 * @example
 * ```tsx
 * import { TatchiPasskeyProvider } from '@tatchi-xyz/sdk/react';
 * import { useDeviceLinking } from '@tatchi-xyz/sdk/react';
 *
 * function DeviceLinker() {
 *   const { linkDevice } = useDeviceLinking({
 *     onDeviceLinked: (result) => console.log('Device linked:', result),
 *     onError: (error) => console.error('Error:', error)
 *   });
 *
 *   return <button onClick={() => linkDevice(qrData, QRScanMode.CAMERA)}>
 *     Link Device
 *   </button>;
 * }
 * ```
 */
export interface UseDeviceLinkingOptions {
  onDeviceLinked?: (result: LinkDeviceResult) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: DeviceLinkingSSEEvent) => void;
  fundingAmount?: string;
}

export interface UseDeviceLinkingReturn {
  linkDevice: (qrData: DeviceLinkingQRData, source: QRScanMode) => Promise<void>;
}

export const useDeviceLinking = (options: UseDeviceLinkingOptions): UseDeviceLinkingReturn => {
  const { tatchi } = useTatchi();
  const {
    onDeviceLinked,
    onError,
    onClose,
    onEvent,
    fundingAmount = '0.05'
  } = options;

  const hasClosedEarlyRef = useRef(false);

  // Use refs for callbacks to avoid dependency changes
  const callbacksRef = useRef({
    onDeviceLinked,
    onError,
    onClose,
    onEvent
  });

  // Update refs when callbacks change
  callbacksRef.current = {
    onDeviceLinked,
    onError,
    onClose,
    onEvent
  };

  // Handle device linking with early close logic
  const linkDevice = useCallback(async (qrData: DeviceLinkingQRData, source: QRScanMode) => {

    const {
      onDeviceLinked,
      onError,
      onClose,
      onEvent
    } = callbacksRef.current;

    try {
      console.log(`useDeviceLinking: Starting device linking from ${source}...`);
      hasClosedEarlyRef.current = false; // Reset for this linking attempt

      const result = await tatchi.linkDeviceWithScannedQRData(qrData, {
        fundingAmount,
        onEvent: (event) => {
          onEvent?.(event);
          console.log(`useDeviceLinking: ${source} linking event -`, event.phase, event.message);
          // Close scanner immediately after QR validation succeeds
          switch (event.phase) {
            case DeviceLinkingPhase.STEP_3_AUTHORIZATION:
              if (event.status === DeviceLinkingStatus.PROGRESS) {
                console.log('useDeviceLinking: QR validation complete - closing scanner while linking continues...');
                hasClosedEarlyRef.current = true;
                onClose?.();
              }
              break;
          }
        },
        onError: (error: any) => {
          console.error(`useDeviceLinking: ${source} linking error -`, error.message);
          onError?.(error);
        }
      });

      console.log(`useDeviceLinking: ${source} linking completed -`, { success: !!result });

      onDeviceLinked?.(result);

    } catch (linkingError: any) {
      console.error(`useDeviceLinking: ${source} linking failed -`, linkingError.message);
      onError?.(linkingError);

      // Close scanner on error if it hasn't been closed early
      if (!hasClosedEarlyRef.current) {
        console.log('useDeviceLinking: Closing scanner due to linking error...');
        onClose?.();
      }
    }
  }, [fundingAmount, tatchi]);

  return {
    linkDevice,
  };
};

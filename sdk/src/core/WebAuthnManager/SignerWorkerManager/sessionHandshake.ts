/**
 * Session Handshake Orchestration for Signer Worker
 *
 * This module provides high-level functions for setting up and validating
 * signing sessions with the signer worker. It orchestrates the complete
 * handshake flow for port attachment so the SecureConfirm worker can deliver WrapKeySeed
 * to the signer worker over a session MessagePort.
 */

import { waitForWrapKeyPortAttach } from './sessionMessages.js';
import { WorkerControlMessage } from '../../workerControlMessages';

/**
 * Attach a WrapKeySeed MessagePort to the signer worker and wait for acknowledgment.
 * This ensures the port is successfully attached before proceeding.
 *
 * Flow:
 * 1. Register ACK listener (avoids race where worker responds before we listen)
 * 2. Send ATTACH_WRAP_KEY_SEED_PORT message with port transfer
 * 3. Wait for ATTACH_WRAP_KEY_SEED_PORT_OK acknowledgment
 *
 * @param worker - The signer worker to attach the port to
 * @param sessionId - The signing session ID
 * @param signerPort - The MessagePort for receiving WrapKeySeed material
 * @param timeoutMs - How long to wait for ACK (default: 2000ms)
 * @throws Error if attachment fails or times out
 */
export async function attachSessionPort(
  worker: Worker,
  sessionId: string,
  signerPort: MessagePort,
  timeoutMs: number = 2000
): Promise<void> {
  // Register the ACK listener BEFORE sending the message to avoid race condition
  const waitPromise = waitForWrapKeyPortAttach(worker, sessionId, timeoutMs);

  // Send the attach command (transfer the port)
  worker.postMessage(
    { type: WorkerControlMessage.ATTACH_WRAP_KEY_SEED_PORT, sessionId },
    [signerPort]
  );

  // Wait for the worker to acknowledge successful attachment
  await waitPromise;
}

export const generateSessionId = (): string => {
  return (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `sign-session-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

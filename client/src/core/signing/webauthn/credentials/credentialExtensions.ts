export type CredentialWithExtensionOutputs = {
  response?: unknown;
  clientExtensionResults?: unknown;
};

export function getPrfResultsFromCredential(credential: unknown): { first?: string; second?: string } {
  try {
    const results = (credential as any)?.clientExtensionResults?.prf?.results as unknown;
    if (!results || typeof results !== 'object') return {};

    const first = typeof (results as any).first === 'string' ? (results as any).first.trim() : '';
    const second = typeof (results as any).second === 'string' ? (results as any).second.trim() : '';

    return {
      ...(first ? { first } : {}),
      ...(second ? { second } : {}),
    };
  } catch {
    return {};
  }
}

export function getPrfFirstB64uFromCredential(credential: unknown): string | null {
  return getPrfResultsFromCredential(credential).first ?? null;
}

export function redactCredentialExtensionOutputs<C extends CredentialWithExtensionOutputs>(
  credential: C,
): C {
  const response = credential.response;
  const responseWithoutExtensions =
    response && typeof response === 'object'
      ? (() => {
          const cloned = { ...(response as Record<string, unknown>) };
          if ('clientExtensionResults' in cloned) cloned.clientExtensionResults = null;
          return cloned;
        })()
      : response;

  return {
    ...credential,
    response: responseWithoutExtensions,
    clientExtensionResults: null,
  } as C;
}

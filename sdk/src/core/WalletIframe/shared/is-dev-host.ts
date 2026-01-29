type EnvHostOptions = {
  hostname?: string;
  nodeEnv?: string;
};

export function isDevHost(opts: EnvHostOptions = {}): boolean {
  const env =
    opts.nodeEnv ??
    (globalThis as { process?: { env?: Record<string, string | undefined> } })?.process?.env?.NODE_ENV;
  if (env && env !== 'production') return true;

  const hostname =
    opts.hostname ??
    (typeof window !== 'undefined' ? (window.location.hostname || '') : '');

  return /localhost|127\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d?)|\.local(?:host)?$/i.test(hostname);
}

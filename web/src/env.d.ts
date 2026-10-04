/// <reference types="svelte" />
/// <reference types="vite/client" />

declare const __APP_VERSION__: string;

declare module '$bridge' {
  import type { Bridge } from './lib/bridge';
  export function createBridge(): Promise<Bridge>;
}

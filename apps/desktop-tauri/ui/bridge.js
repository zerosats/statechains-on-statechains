// The webview's only path to a backend. Inside Tauri it uses the shell's
// commands and `wallet` events; a plain browser (visual QA) gets the mock.

export async function connectBridge() {
  const tauri = window.__TAURI__;
  if (!tauri) {
    const { createMockBridge } = await import('./mock/bridge.js');
    return createMockBridge(new URLSearchParams(location.search));
  }
  const { invoke } = tauri.core;
  return {
    appInfo: () => invoke('app_info'),
    start: () => invoke('start'),
    perform: (action, args) => invoke('perform', { action, args }),
    isRunning: () => invoke('is_running'),
    qrSvg: value => invoke('qr_svg', { value }),
    onWallet: handler => tauri.event.listen('wallet', ({ payload }) => handler(payload)),
  };
}

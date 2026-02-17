import { writable, derived } from 'svelte/store';

// Scan status store
export const scanStatus = writable({
  isScanning: false,
  progress: 0,
  currentPhase: '',
});

// Devices store
export const devices = writable([]);

// Overall security score
export const overallScore = derived(devices, ($devices) => {
  if ($devices.length === 0) return 0;

  const scores = $devices.map((device) => {
    switch (device.securityLevel) {
      case 'safe':
        return 100;
      case 'warning':
        return 60;
      case 'danger':
        return 20;
      default:
        return 50;
    }
  });

  return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
});

// Start scan function
export async function startScan() {
  scanStatus.set({
    isScanning: true,
    progress: 0,
    currentPhase: '初期化中...',
  });

  try {
    const { invoke } = await import('@tauri-apps/api/core');
    const { listen } = await import('@tauri-apps/api/event');

    // Reset devices
    devices.set([]);

    // Listen for progress events
    const unlisten = await listen('scan-progress', (event) => {
      const { phase, progress } = event.payload;
      scanStatus.update((s) => ({ ...s, currentPhase: phase, progress }));
    });

    // Start scan (Level 2 for active scanning)
    const result = await invoke('start_scan', { level: 'level2' });
    
    // Sort devices by IP for better readability
    result.sort((a, b) => {
        const numA = a.ip.split('.').map(Number);
        const numB = b.ip.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            if (numA[i] !== numB[i]) return numA[i] - numB[i];
        }
        return 0;
    });

    devices.set(result);
    unlisten();

  } catch (error) {
    console.error('Scan failed:', error);
    scanStatus.update(s => ({ 
        ...s, 
        currentPhase: `エラーが発生しました: ${error}`,
        progress: 100 
    }));
  } finally {
    scanStatus.update((s) => ({
      ...s,
      isScanning: false,
      progress: 100,
      currentPhase: s.currentPhase.startsWith('エラー') ? s.currentPhase : '完了',
    }));
  }
}

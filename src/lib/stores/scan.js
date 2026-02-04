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

// Start scan function (placeholder - will be replaced with Tauri command)
export async function startScan() {
  scanStatus.set({
    isScanning: true,
    progress: 0,
    currentPhase: 'ネットワークを検索中...',
  });

  // Simulate scanning phases
  const phases = [
    { phase: 'ネットワークを検索中...', progress: 10 },
    { phase: 'デバイスを検出中...', progress: 30 },
    { phase: 'MACアドレスを解析中...', progress: 50 },
    { phase: 'ポートをスキャン中...', progress: 70 },
    { phase: 'セキュリティを診断中...', progress: 90 },
    { phase: '完了', progress: 100 },
  ];

  for (const { phase, progress } of phases) {
    await new Promise((resolve) => setTimeout(resolve, 800));
    scanStatus.update((s) => ({ ...s, currentPhase: phase, progress }));
  }

  // Mock device data (will be replaced with real scan results)
  devices.set([
    {
      id: '1',
      name: 'Buffalo ルーター',
      type: 'router',
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:FF',
      vendor: 'Buffalo Inc.',
      securityLevel: 'warning',
      issues: ['管理画面がHTTPで公開されています', 'UPnPが有効です'],
    },
    {
      id: '2',
      name: 'スマートスピーカー',
      type: 'smart_speaker',
      ip: '192.168.1.10',
      mac: '11:22:33:44:55:66',
      vendor: 'Amazon',
      securityLevel: 'safe',
      issues: [],
    },
    {
      id: '3',
      name: 'ネットワークカメラ',
      type: 'camera',
      ip: '192.168.1.20',
      mac: '77:88:99:AA:BB:CC',
      vendor: 'TP-Link',
      securityLevel: 'danger',
      issues: [
        'デフォルトパスワードが使用されています',
        'ファームウェアが古いバージョンです',
        'Telnetポートが開放されています',
      ],
    },
  ]);

  scanStatus.set({
    isScanning: false,
    progress: 100,
    currentPhase: '完了',
  });
}

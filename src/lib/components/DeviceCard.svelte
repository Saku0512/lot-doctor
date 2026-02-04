<script>
  export let device;

  const securityLevelColors = {
    safe: 'bg-green-100 text-green-800 border-green-200',
    warning: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    danger: 'bg-red-100 text-red-800 border-red-200',
  };

  const securityLevelLabels = {
    safe: '安全',
    warning: '注意',
    danger: '危険',
  };

  function getDeviceIcon(type) {
    const icons = {
      router: 'M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.14 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0',
      camera: 'M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z',
      smart_speaker: 'M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z',
      tv: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
      default: 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z',
    };
    return icons[type] || icons.default;
  }
</script>

<div class="border border-slate-200 rounded-lg p-4 hover:border-slate-300 transition-colors">
  <div class="flex items-start gap-4">
    <!-- Device Icon -->
    <div class="w-12 h-12 bg-slate-100 rounded-lg flex items-center justify-center flex-shrink-0">
      <svg class="w-6 h-6 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={getDeviceIcon(device.type)} />
      </svg>
    </div>

    <!-- Device Info -->
    <div class="flex-1 min-w-0">
      <div class="flex items-center gap-2 mb-1">
        <h3 class="font-medium text-slate-800 truncate">{device.name || '不明なデバイス'}</h3>
        <span class="px-2 py-0.5 text-xs font-medium rounded-full border {securityLevelColors[device.securityLevel]}">
          {securityLevelLabels[device.securityLevel]}
        </span>
      </div>
      <div class="text-sm text-slate-500 space-y-0.5">
        <p>IP: {device.ip}</p>
        <p>MAC: {device.mac}</p>
        {#if device.vendor}
          <p>メーカー: {device.vendor}</p>
        {/if}
      </div>
    </div>

    <!-- Action Button -->
    <button class="text-primary-600 hover:text-primary-700 p-2 hover:bg-primary-50 rounded-lg transition-colors">
      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
      </svg>
    </button>
  </div>

  {#if device.issues && device.issues.length > 0}
    <div class="mt-3 pt-3 border-t border-slate-100">
      <p class="text-sm font-medium text-slate-700 mb-2">検出された問題:</p>
      <ul class="text-sm text-slate-600 space-y-1">
        {#each device.issues as issue}
          <li class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 bg-red-500 rounded-full"></span>
            {issue}
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>

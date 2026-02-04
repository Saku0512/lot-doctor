<script>
  import { scanStatus, devices, startScan } from '../stores/scan.js';
  import DeviceCard from './DeviceCard.svelte';
  import SecurityScore from './SecurityScore.svelte';
</script>

<div class="space-y-8">
  <!-- Scan Control Section -->
  <section class="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
      <div>
        <h2 class="text-lg font-semibold text-slate-800">ネットワークスキャン</h2>
        <p class="text-sm text-slate-500 mt-1">
          ホームネットワーク上のIoTデバイスを検出し、セキュリティ状態を診断します
        </p>
      </div>
      <button
        on:click={startScan}
        disabled={$scanStatus.isScanning}
        class="px-6 py-3 bg-primary-600 text-white font-medium rounded-lg
               hover:bg-primary-700 disabled:bg-slate-300 disabled:cursor-not-allowed
               transition-colors flex items-center gap-2"
      >
        {#if $scanStatus.isScanning}
          <span class="animate-spin w-5 h-5 border-2 border-white border-t-transparent rounded-full"></span>
          スキャン中...
        {:else}
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          診断を開始
        {/if}
      </button>
    </div>

    {#if $scanStatus.isScanning}
      <div class="mt-6">
        <div class="flex justify-between text-sm text-slate-600 mb-2">
          <span>{$scanStatus.currentPhase}</span>
          <span>{$scanStatus.progress}%</span>
        </div>
        <div class="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
          <div
            class="h-full bg-primary-600 transition-all duration-300"
            style="width: {$scanStatus.progress}%"
          ></div>
        </div>
      </div>
    {/if}
  </section>

  <!-- Results Section -->
  {#if $devices.length > 0}
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Security Score -->
      <div class="lg:col-span-1">
        <SecurityScore />
      </div>

      <!-- Device List -->
      <div class="lg:col-span-2">
        <section class="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
          <h2 class="text-lg font-semibold text-slate-800 mb-4">
            検出されたデバイス ({$devices.length}台)
          </h2>
          <div class="space-y-4">
            {#each $devices as device (device.id)}
              <DeviceCard {device} />
            {/each}
          </div>
        </section>
      </div>
    </div>
  {:else if !$scanStatus.isScanning}
    <div class="text-center py-16">
      <div class="w-20 h-20 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
        <svg class="w-10 h-10 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.14 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
        </svg>
      </div>
      <h3 class="text-lg font-medium text-slate-700 mb-2">デバイスが見つかりません</h3>
      <p class="text-slate-500">「診断を開始」ボタンをクリックして、ネットワークスキャンを実行してください</p>
    </div>
  {/if}
</div>

<script>
  import { overallScore } from '../stores/scan.js';

  $: scoreColor = $overallScore >= 80 ? 'text-green-500' : $overallScore >= 50 ? 'text-yellow-500' : 'text-red-500';
  $: scoreLabel = $overallScore >= 80 ? '良好' : $overallScore >= 50 ? '注意' : '危険';
  $: scoreBg = $overallScore >= 80 ? 'bg-green-50' : $overallScore >= 50 ? 'bg-yellow-50' : 'bg-red-50';
  $: strokeColor = $overallScore >= 80 ? '#22c55e' : $overallScore >= 50 ? '#f59e0b' : '#ef4444';

  const circumference = 2 * Math.PI * 45;
  $: strokeDashoffset = circumference - ($overallScore / 100) * circumference;
</script>

<section class="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
  <h2 class="text-lg font-semibold text-slate-800 mb-4">セキュリティスコア</h2>

  <div class="flex flex-col items-center">
    <!-- Score Circle -->
    <div class="relative w-40 h-40 mb-4">
      <svg class="w-40 h-40 transform -rotate-90">
        <circle
          cx="80"
          cy="80"
          r="45"
          stroke="#e2e8f0"
          stroke-width="10"
          fill="none"
        />
        <circle
          cx="80"
          cy="80"
          r="45"
          stroke={strokeColor}
          stroke-width="10"
          fill="none"
          stroke-linecap="round"
          stroke-dasharray={circumference}
          stroke-dashoffset={strokeDashoffset}
          class="transition-all duration-500"
        />
      </svg>
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <span class="text-4xl font-bold {scoreColor}">{$overallScore}</span>
        <span class="text-sm text-slate-500">/ 100</span>
      </div>
    </div>

    <!-- Score Label -->
    <div class="text-center">
      <span class="inline-block px-4 py-1.5 rounded-full text-sm font-medium {scoreBg} {scoreColor}">
        {scoreLabel}
      </span>
    </div>

    <!-- Score Breakdown -->
    <div class="w-full mt-6 space-y-3">
      <div class="flex justify-between text-sm">
        <span class="text-slate-600">パスワード安全性</span>
        <span class="font-medium text-slate-800">良好</span>
      </div>
      <div class="flex justify-between text-sm">
        <span class="text-slate-600">ポート開放状況</span>
        <span class="font-medium text-slate-800">注意</span>
      </div>
      <div class="flex justify-between text-sm">
        <span class="text-slate-600">ファームウェア</span>
        <span class="font-medium text-slate-800">確認中</span>
      </div>
      <div class="flex justify-between text-sm">
        <span class="text-slate-600">暗号化</span>
        <span class="font-medium text-slate-800">良好</span>
      </div>
    </div>
  </div>
</section>

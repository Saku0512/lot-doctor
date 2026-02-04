<script>
  import Header from './lib/components/Header.svelte';
  import Dashboard from './lib/components/Dashboard.svelte';
  import { scanStatus } from './lib/stores/scan.js';
</script>

<div class="min-h-screen bg-slate-50">
  <Header />
  <main class="container mx-auto px-4 py-8">
    <Dashboard />
  </main>
</div>

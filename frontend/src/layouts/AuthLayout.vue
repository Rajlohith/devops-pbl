<template>
  <div class="flex min-h-screen flex-col items-center justify-center bg-slate-50 px-4 py-10">
    <div class="mb-6 flex items-center gap-2.5">
      <svg
        class="h-8 w-8 text-blue-600"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2.25"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d="M2 12h5l3-8 4 16 3-8h5" />
      </svg>
      <span class="text-2xl font-semibold tracking-tight text-slate-900">NetScope</span>
    </div>
    <main class="w-full max-w-sm rounded-lg bg-white p-6 shadow-sm ring-1 ring-slate-200">
      <RouterView />
    </main>
    <p class="mt-6 text-xs text-slate-400">Network capture analysis</p>
  </div>
</template>

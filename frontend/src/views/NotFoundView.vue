<template>
  <div class="mx-auto max-w-md py-20 text-center">
    <p class="font-mono text-4xl font-semibold text-slate-300">404</p>
    <h2 class="mt-3 text-lg font-semibold text-slate-900">Page not found</h2>
    <p class="mt-1 text-slate-500">That page doesn't exist.</p>
    <RouterLink :to="{ name: 'dashboard' }" class="btn btn-primary mt-6">Back to the dashboard</RouterLink>
  </div>
</template>

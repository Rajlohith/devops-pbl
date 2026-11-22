import { getCurrentInstance, onBeforeUnmount } from 'vue'

/**
 * Call `task` repeatedly, waiting `interval` ms *after* each run finishes (so slow requests
 * never overlap). Stops by itself when the component unmounts.
 *
 * @param {() => Promise<unknown> | unknown} task
 * @param {{interval?: number}} [options]
 */
export function usePolling(task, { interval = 2000 } = {}) {
  let timer = null
  let running = false

  async function tick() {
    timer = null
    if (!running) return
    try {
      await task()
    } catch {
      /* transient failures are retried on the next tick */
    }
    if (running) timer = setTimeout(tick, interval)
  }

  function start() {
    if (running) return
    running = true
    timer = setTimeout(tick, interval)
  }

  function stop() {
    running = false
    clearTimeout(timer)
    timer = null
  }

  if (getCurrentInstance()) onBeforeUnmount(stop)

  return { start, stop, isRunning: () => running }
}

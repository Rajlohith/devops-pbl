import { beforeEach, vi } from 'vitest'

// jsdom has no canvas, so Chart.js is replaced by a recorder: tests assert on the chart
// configuration the app builds (type, labels, data) rather than on pixels. Real rendering is
// covered by the Playwright tests in tests/e2e.
vi.mock('chart.js', () => {
  class Chart {
    static instances = []
    static register = vi.fn()
    static defaults = { font: {}, color: '', borderColor: '' }
    constructor(canvas, config) {
      this.canvas = canvas
      this.config = config
      this.data = config.data
      this.options = config.options
      this.destroyed = false
      this.update = vi.fn()
      Chart.instances.push(this)
    }
    destroy() {
      this.destroyed = true
    }
  }
  const element = {}
  return {
    Chart,
    ArcElement: element, BarController: element, BarElement: element, CategoryScale: element,
    DoughnutController: element, Filler: element, Legend: element, LineController: element,
    LineElement: element, LinearScale: element, PointElement: element, Tooltip: element,
  }
})

beforeEach(async () => {
  const { Chart } = await import('chart.js')
  Chart.instances.length = 0
})

// jsdom does not implement scrolling; the router calls it after navigations.
window.scrollTo = vi.fn()
Element.prototype.scrollIntoView = vi.fn()

// Fail loudly (and name the URL) if a test forgets to mock an API call, instead of letting
// jsdom try to reach a real server.
import axios from 'axios'
axios.defaults.adapter = (config) =>
  Promise.reject(new Error(`Unmocked network request: ${config.method?.toUpperCase()} ${config.url}`))

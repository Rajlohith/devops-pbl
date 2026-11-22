import { useCaptureDetailStore } from './captureDetail'
import { useCapturesStore } from './captures'
import { useDashboardStore } from './dashboard'

/** Forget every user-specific piece of data held in memory (on sign-out or session expiry). */
export function resetSessionData() {
  useCapturesStore().reset()
  useDashboardStore().reset()
  useCaptureDetailStore().reset()
}

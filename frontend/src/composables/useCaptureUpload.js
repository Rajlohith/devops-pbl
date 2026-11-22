import { computed, ref, shallowRef } from 'vue'

import { capturesApi } from '@/api/captures'
import { bytes } from '@/utils/format'

export const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap']

export const hasAllowedExtension = (name) =>
  ALLOWED_EXTENSIONS.some((ext) => name.toLowerCase().endsWith(ext))

/**
 * Choosing, validating and uploading one capture file, with progress.
 * The server re-validates the contents; the extension check here is only a courtesy.
 */
export function useCaptureUpload() {
  const file = shallowRef(null)
  const analyze = ref(true)
  const uploading = ref(false)
  const progress = ref(0) // 0..1
  const error = ref('')
  const uploaded = ref(null) // the capture record after a successful upload

  const fileLabel = computed(() =>
    file.value ? `${file.value.name} (${bytes(file.value.size)})` : 'No file selected',
  )
  const canUpload = computed(() => Boolean(file.value) && !uploading.value && !error.value)

  function pick(chosen) {
    uploaded.value = null
    error.value = ''
    progress.value = 0
    if (!chosen) {
      file.value = null
      return
    }
    file.value = chosen
    if (!hasAllowedExtension(chosen.name)) {
      error.value = 'Unsupported file type. Choose a .pcap, .pcapng or .cap file.'
    }
  }

  /** @returns {Promise<object|null>} the created capture, or null if it failed */
  async function upload() {
    if (!canUpload.value) return null
    uploading.value = true
    progress.value = 0
    error.value = ''
    uploaded.value = null
    try {
      const capture = await capturesApi.upload(file.value, {
        analyze: analyze.value,
        onProgress: (fraction) => {
          progress.value = fraction
        },
      })
      uploaded.value = capture
      file.value = null
      progress.value = 0
      return capture
    } catch (e) {
      error.value = e.isNetworkError
        ? 'Upload failed: could not reach the server.'
        : e.message || 'Upload failed.'
      progress.value = 0
      return null
    } finally {
      uploading.value = false
    }
  }

  return { file, analyze, uploading, progress, error, uploaded, fileLabel, canUpload, pick, upload }
}

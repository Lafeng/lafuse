(function () {
  const getFileHash = async (file) => {
    const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
    return [...new Uint8Array(digest)]
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  };

  const findExistingUpload = async (sha256, size) => {
    if (!sha256) return null;
    const params = new URLSearchParams({ sha256 });
    if (Number.isFinite(size)) params.set('size', String(size));
    const response = await fetch(`/api.exists?${params}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.exists ? data.media : null;
  };

  const uploadWithProgress = (url, formData, onProgress) => new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    });
    xhr.onload = () => {
      let payload = null;
      try {
        payload = JSON.parse(xhr.responseText);
      } catch {
        payload = null;
      }

      if (xhr.status >= 200 && xhr.status < 300) {
        payload ? resolve(payload) : reject(new Error('响应解析失败'));
        return;
      }

      reject(new Error(payload?.error ?? `上传失败: HTTP ${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error('网络错误，请检查网络连接'));
    xhr.ontimeout = () => reject(new Error('上传超时，请重试'));
    xhr.timeout = 120000;
    xhr.open('POST', url);
    xhr.send(formData);
  });

  window.LafuseUploadTransport = {
    findExistingUpload,
    getFileHash,
    uploadWithProgress,
  };
}());

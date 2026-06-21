(function () {
  const generateImageThumbnail = async (file) => {
    try {
      const bitmap = await createImageBitmap(file);
      const maxDim = 520;
      const scale = Math.min(maxDim / bitmap.width, maxDim / bitmap.height, 1);
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      bitmap.close?.();
      const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.84));
      return blob ? new File([blob], 'thumb.jpg', { type: 'image/jpeg' }) : null;
    } catch {
      return null;
    }
  };

  const generateVideoThumbnail = (file) => new Promise(resolve => {
    const video = document.createElement('video');
    const objectUrl = URL.createObjectURL(file);
    let settled = false;
    const timeout = setTimeout(() => finish(null), 5000);

    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      URL.revokeObjectURL(objectUrl);
      resolve(value);
    };

    const capture = () => {
      try {
        const maxDim = 520;
        const w = video.videoWidth || 640;
        const h = video.videoHeight || 360;
        const scale = Math.min(maxDim / w, maxDim / h, 1);
        const canvas = document.createElement('canvas');
        canvas.width = Math.max(1, Math.round(w * scale));
        canvas.height = Math.max(1, Math.round(h * scale));
        canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
        canvas.toBlob(blob => {
          finish(blob ? new File([blob], 'thumb.jpg', { type: 'image/jpeg' }) : null);
        }, 'image/jpeg', 0.84);
      } catch {
        finish(null);
      }
    };

    video.muted = true;
    video.playsInline = true;
    video.preload = 'metadata';
    video.addEventListener('error', () => finish(null));
    video.addEventListener('loadedmetadata', () => {
      video.currentTime = Number.isFinite(video.duration) ? Math.min(video.duration * 0.1, 1) : 0;
    });
    video.addEventListener('seeked', capture, { once: true });
    video.addEventListener('loadeddata', () => setTimeout(capture, 260), { once: true });
    video.src = objectUrl;
    video.load();
  });

  const compressImage = async (file) => {
    const bitmap = await createImageBitmap(file);
    const maxWidth = 2560;
    const scale = Math.min(1, maxWidth / bitmap.width);
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close?.();
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.86));
    if (!blob || blob.size >= file.size) return file;
    const dotIndex = file.name.lastIndexOf('.');
    const baseName = dotIndex > 0 ? file.name.slice(0, dotIndex) : file.name;
    return new File([blob], `${baseName}.jpg`, { type: 'image/jpeg' });
  };

  window.LafuseImageTools = {
    compressImage,
    generateImageThumbnail,
    generateVideoThumbnail,
  };
}());

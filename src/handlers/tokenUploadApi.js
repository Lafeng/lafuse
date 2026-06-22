import { json } from '../http.js';
import { getApiTokenUser } from '../authToken.js';
import { uploadMedia } from '../services/mediaUploadService.js';
import { clearMediaListCache } from './mediaApi.js';

export async function apiV1Ping({ request, config }) {
  const tokenUser = await getApiTokenUser(request, config);
  if (!tokenUser) return json({ ok: false, error: 'Unauthorized' }, 401);
  return json({
    ok: true,
    user: {
      username: tokenUser.username,
      tokenName: tokenUser.tokenName,
    },
  });
}

export async function apiV1Upload({ request, config }) {
  const tokenUser = await getApiTokenUser(request, config);
  if (!tokenUser) return json({ ok: false, error: 'Unauthorized' }, 401);

  try {
    const contentType = request.headers.get('Content-Type') || '';
    if (!contentType.toLowerCase().includes('multipart/form-data')) {
      return json({ ok: false, error: 'Expected multipart/form-data' }, 415);
    }
    const formData = await request.formData();
    const file = formData.get('file');
    const rawSha256 = formData.get('sha256') || '';
    const payload = await uploadMedia({
      request,
      config,
      user: tokenUser,
      file,
      thumb: formData.get('thumb'),
      rawSha256,
      uploadSource: 'api',
    });
    clearMediaListCache();

    return json({
      ok: true,
      url: payload.data,
      data: {
        id: payload.id,
        originalName: payload.originalName,
        url: payload.data,
        thumbUrl: payload.thumbUrl,
        hasThumb: payload.hasThumb,
        uploadSource: payload.uploadSource,
        reused: payload.reused,
      },
    });
  } catch (error) {
    console.error('API 上传错误:', error);
    return json({ ok: false, error: error.message }, error.status || 500);
  }
}

const UPLOADER_ID = 'lafuse';

const getConfig = ctx => ctx.getConfig(`picBed.${UPLOADER_ID}`) || {};

const getFileBuffer = img => {
  if (img.buffer) return img.buffer;
  if (img.base64Image) return Buffer.from(img.base64Image, 'base64');
  return null;
};

const parseExtname = img => {
  if (img.extname) return img.extname.startsWith('.') ? img.extname : `.${img.extname}`;
  return '.png';
};

const getEndpoint = endpoint => {
  const value = String(endpoint || '').trim().replace(/\/+$/, '');
  if (!value) throw new Error('Lafuse endpoint is required');
  return value.endsWith('/api/v1/upload') ? value : `${value}/api/v1/upload`;
};

const handle = async ctx => {
  const config = getConfig(ctx);
  const endpoint = getEndpoint(config.endpoint);
  const token = String(config.token || '').trim();
  if (!token) throw new Error('Lafuse API token is required');

  for (const img of ctx.output) {
    const buffer = getFileBuffer(img);
    if (!buffer) throw new Error(`Missing image buffer: ${img.fileName || 'unknown'}`);

    const fileName = img.fileName || `image${parseExtname(img)}`;
    const response = await ctx.request({
      method: 'POST',
      url: endpoint,
      headers: {
        Authorization: `Bearer ${token}`,
        'User-Agent': 'PicGo-Lafuse',
      },
      formData: {
        file: {
          value: buffer,
          options: {
            filename: fileName,
          },
        },
      },
    });

    const body = typeof response === 'string' ? JSON.parse(response) : response;
    const uploadedUrl = body?.data?.url || body?.url;
    if (!body || body.ok !== true || !uploadedUrl) {
      const message = body?.error || 'Lafuse upload failed';
      ctx.emit('notification', {
        title: 'Lafuse upload failed',
        body: message,
      });
      throw new Error(message);
    }

    delete img.base64Image;
    delete img.buffer;
    img.imgUrl = uploadedUrl;
    img.url = uploadedUrl;
  }

  return ctx;
};

const config = ctx => {
  const userConfig = getConfig(ctx);
  return [
    {
      name: 'endpoint',
      type: 'input',
      alias: 'Lafuse Endpoint',
      message: 'Lafuse site URL or /api/v1/upload URL',
      default: userConfig.endpoint || '',
      required: true,
    },
    {
      name: 'token',
      type: 'password',
      alias: 'API Token',
      message: 'Lafuse API token',
      default: userConfig.token || '',
      required: true,
    },
  ];
};

module.exports = ctx => {
  const register = () => {
    ctx.helper.uploader.register(UPLOADER_ID, {
      name: 'Lafuse',
      handle,
      config,
    });
  };

  return {
    register,
    uploader: UPLOADER_ID,
  };
};

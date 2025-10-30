import { createHash } from 'crypto';

export function uzcardAuthHash(timestamp?: number) {
  if (timestamp) {
    const secretKey = process.env.UZCARD_SECRET_KEY;
    if (!secretKey) {
      throw new Error('UZCARD_SECRET_KEY must be defined in environment variables');
    }
    const data = `${timestamp}${secretKey}`;
    const signature = createHash('sha256').update(data).digest('hex');
    return { signature };
  }

  const login = process.env.UZCARD_LOGIN;
  const password = process.env.UZCARD_PASSWORD;

  if (!login || !password) {
    throw new Error(
      'UZCARD_LOGIN and UZCARD_PASSWORD must be defined in environment variables',
    );
  }

  // Ensure proper UTF-8 encoding
  const credentials = `${login}:${password}`;
  const base64Credentials = Buffer.from(credentials, 'utf8').toString('base64');

  return `Basic ${base64Credentials}`;
}

export function  uzcardAuthHash() {
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

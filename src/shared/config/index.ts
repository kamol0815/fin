import * as dotenv from 'dotenv';
import { cleanEnv, num, str } from 'envalid';

export type SubscriptionType = 'basic';

dotenv.config();

export const config = cleanEnv(process.env, {
  APP_PORT: num(),
  BOT_TOKEN: str(),
  MONGODB_URI: str(),
  CHANNEL_ID: str(),
  NODE_ENV: str({
    choices: ['development', 'production'],
    default: 'development',
  }),

  CLICK_SERVICE_ID: str(),
  CLICK_MERCHANT_ID: str(),
  CLICK_SECRET: str(),

  UZCARD_SECRET_KEY: str(),

  PAYME_MERCHANT_ID: str(),
  PAYME_LOGIN: str(),
  PAYME_PASSWORD: str(),
  PAYME_PASSWORD_TEST: str(),
  PAYMENT_LINK_SECRET: str({ default: 'replace-me-with-secure-secret' }),
  PAYMENT_LINK_BASE_URL: str({ default: '' }),
  SUBSCRIPTION_BASE_URL: str({ default: '' }),
  SUBSCRIPTION_MANAGEMENT_BASE_URL: str({ default: '' }),
  SUBSCRIPTION_TERMS_URL: str({
    default: 'https://telegra.ph/Yulduzlar-Bashorati--OMMAVIY-OFERTA-10-29',
  }),
  API_PREFIX: str({ default: 'api' }),
  INTRO_STICKER_ID: str({ default: '' }),
});

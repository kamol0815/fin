import { config } from '../config';

/**
 * Click bir martalik to'lov linkini yaratish
 * 
 * @param userId - Foydalanuvchi ID
 * @param planId - Reja ID
 * @param amount - To'lov summasi (tiyin)
 * @returns To'lov linki
 */
export function generateClickOnetimeLink(
    userId: string,
    planId: string,
    amount: number
): string {
    const CLICK_SERVICE_ID = process.env.CLICK_SERVICE_ID || '76216';
    const CLICK_MERCHANT_ID = process.env.CLICK_MERCHANT_ID || '7269';
    const RETURN_URL = 'https://t.me/Yulduz_bashorati_bot';

    // Click to'lov linki
    const paymentUrl = new URL('https://my.click.uz/services/pay');

    paymentUrl.searchParams.set('service_id', CLICK_SERVICE_ID);
    paymentUrl.searchParams.set('merchant_id', CLICK_MERCHANT_ID);
    paymentUrl.searchParams.set('amount', amount.toString());
    paymentUrl.searchParams.set('transaction_param', userId); // userId
    paymentUrl.searchParams.set('additional_param3', planId); // planId
    paymentUrl.searchParams.set('return_url', RETURN_URL);

    return paymentUrl.toString();
}

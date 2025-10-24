import { Injectable, Logger } from '@nestjs/common';
import { createHash } from 'crypto';
import { UserModel } from 'src/shared/database/models/user.model';
import { Plan } from 'src/shared/database/models/plans.model';
import { Transaction } from 'src/shared/database/models/transactions.model';
import { UserSubscription } from 'src/shared/database/models/user-subscription.model';

@Injectable()
export class ClickOnetimeService {
    private readonly logger = new Logger(ClickOnetimeService.name);
    private readonly clickServiceId = process.env.CLICK_SERVICE_ID;
    private readonly clickMerchantId = process.env.CLICK_MERCHANT_ID;
    private readonly clickSecretKey = process.env.CLICK_SECRET;
    private readonly clickMerchantUserId = process.env.CLICK_MERCHANT_USER_ID;
    private readonly returnUrl = 'https://t.me/Yulduz_bashorati_bot';

    /**
     * To'lov linkini generatsiya qilish
     */
    generatePaymentLink(userId: string, planId: string, amount: string): string {
        const merchantTransId = `${userId}.${planId}`;

        const paymentLink = `https://my.click.uz/services/pay?service_id=${this.clickServiceId}&merchant_id=${this.clickMerchantId}&amount=${amount}&transaction_param=${userId}&additional_param3=${planId}&return_url=${encodeURIComponent(this.returnUrl)}`;

        this.logger.log(`Generated payment link: ${paymentLink}`);

        return paymentLink;
    }

    /**
     * Click'dan kelgan callback'ni qayta ishlash
     */
    async handleClickCallback(clickReqBody: any) {
        const {
            click_trans_id,
            service_id,
            click_paydoc_id,
            merchant_trans_id,
            amount,
            action,
            error,
            error_note,
            sign_time,
            sign_string,
            param2, // planId
        } = clickReqBody;

        this.logger.log(`clickReqBody: ${JSON.stringify(clickReqBody)}`);

        // Sign stringni tekshirish
        const isValidSign = this.verifySignature(clickReqBody);
        if (!isValidSign) {
            this.logger.error('Invalid signature');
            return {
                click_trans_id,
                merchant_trans_id,
                error: -1,
                error_note: 'Invalid signature'
            };
        }

        // Action type bo'yicha ishlov berish
        if (action == 0) {
            // PREPARE - To'lovni tekshirish
            return await this.prepareTransaction(clickReqBody);
        } else if (action == 1) {
            // COMPLETE - To'lovni yakunlash
            return await this.completeTransaction(clickReqBody);
        }

        return {
            click_trans_id,
            merchant_trans_id,
            error: -3,
            error_note: 'Unknown action'
        };
    }

    /**
     * To'lovni tayyorlash (action=0)
     */
    private async prepareTransaction(clickReqBody: any) {
        const {
            click_trans_id,
            merchant_trans_id,
            amount,
            param2, // planId
        } = clickReqBody;

        try {
            this.logger.log(`Preparing transaction ${JSON.stringify({ clickReqBody })}`);

            const userId = merchant_trans_id.split('.')[0] || merchant_trans_id;
            const planId = merchant_trans_id.split('.')[1] || param2;

            if (!planId) {
                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_prepare_id: null,
                    error: -5,
                    error_note: 'Plan ID not found'
                };
            }

            // User va Plan mavjudligini tekshirish
            const user = await UserModel.findById(userId);
            if (!user) {
                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_prepare_id: null,
                    error: -5,
                    error_note: 'User not found'
                };
            }

            const plan = await Plan.findById(planId);
            if (!plan) {
                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_prepare_id: null,
                    error: -5,
                    error_note: 'Plan not found'
                };
            }

            // Summani tekshirish
            if (Number(amount) !== plan.price) {
                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_prepare_id: null,
                    error: -2,
                    error_note: 'Incorrect amount'
                };
            }

            // Transaction yaratish
            const transaction = await Transaction.create({
                userId,
                planId,
                amount: Number(amount),
                transId: click_trans_id,
                state: 0, // PREPARED
                provider: 'click',
                status: 'PENDING',
            });

            return {
                click_trans_id,
                merchant_trans_id,
                merchant_prepare_id: transaction._id.toString(),
                error: 0,
                error_note: 'Success'
            };
        } catch (error) {
            this.logger.error(`Error in prepareTransaction: ${error.message}`, error.stack);
            return {
                click_trans_id,
                merchant_trans_id,
                merchant_prepare_id: null,
                error: -1,
                error_note: 'Internal error'
            };
        }
    }

    /**
     * To'lovni yakunlash (action=1)
     */
    private async completeTransaction(clickReqBody: any) {
        const {
            click_trans_id,
            merchant_trans_id,
            merchant_prepare_id,
            error,
        } = clickReqBody;

        try {
            this.logger.log(`Completing transaction ${JSON.stringify({ clickReqBody })}`);

            if (error !== 0) {
                // To'lov muvaffaqiyatsiz
                await Transaction.updateOne(
                    { _id: merchant_prepare_id },
                    {
                        $set: {
                            state: -1, // FAILED
                            status: 'FAILED',
                            reason: error,
                            cancelTime: new Date()
                        }
                    }
                );

                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_confirm_id: merchant_prepare_id,
                    error: -6,
                    error_note: 'Payment failed'
                };
            }

            // To'lovni yakunlash
            const transaction = await Transaction.findById(merchant_prepare_id);

            if (!transaction) {
                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_confirm_id: null,
                    error: -6,
                    error_note: 'Transaction not found'
                };
            }

            if (transaction.state !== 0) {
                return {
                    click_trans_id,
                    merchant_trans_id,
                    merchant_confirm_id: merchant_prepare_id,
                    error: -4,
                    error_note: 'Already processed'
                };
            }

            // Transaction'ni yangilash
            await Transaction.updateOne(
                { _id: merchant_prepare_id },
                {
                    $set: {
                        state: 1, // COMPLETED
                        status: 'PAID',
                        performTime: new Date()
                    }
                }
            );

            // User'ga obunani aktivlashtirish
            const userId = transaction.userId;
            const planId = transaction.planId;
            const plan = await Plan.findById(planId);

            if (plan) {
                const startDate = new Date();
                const endDate = new Date();
                endDate.setDate(endDate.getDate() + plan.duration);

                await UserSubscription.create({
                    user: userId,
                    plan: planId,
                    subscriptionType: 'onetime',
                    startDate,
                    endDate,
                    isActive: true,
                    status: 'active',
                    paidAmount: transaction.amount,
                    isTrial: false,
                });

                // User'ni yangilash
                await UserModel.findByIdAndUpdate(userId, {
                    $set: {
                        subscriptionType: 'onetime',
                        subscriptionStart: startDate,
                        subscriptionEnd: endDate,
                        isActive: true,
                    },
                    $push: {
                        plans: planId
                    }
                });

                this.logger.log(`Subscription activated for user ${userId}`);
            }

            return {
                click_trans_id,
                merchant_trans_id,
                merchant_confirm_id: merchant_prepare_id,
                error: 0,
                error_note: 'Success'
            };
        } catch (error) {
            this.logger.error(`Error in completeTransaction: ${error.message}`, error.stack);
            return {
                click_trans_id,
                merchant_trans_id,
                merchant_confirm_id: merchant_prepare_id,
                error: -1,
                error_note: 'Internal error'
            };
        }
    }

    /**
     * Signature tekshirish
     */
    private verifySignature(clickReqBody: any): boolean {
        const {
            click_trans_id,
            service_id,
            merchant_trans_id,
            amount,
            action,
            sign_time,
            sign_string,
            merchant_prepare_id = '',
        } = clickReqBody;

        let signString: string;

        if (action == 0) {
            signString = `${click_trans_id}${service_id}${this.clickSecretKey}${merchant_trans_id}${amount}${action}${sign_time}`;
        } else if (action == 1) {
            signString = `${click_trans_id}${service_id}${this.clickSecretKey}${merchant_trans_id}${merchant_prepare_id}${amount}${action}${sign_time}`;
        } else {
            return false;
        }

        const hash = createHash('md5').update(signString).digest('hex');

        return hash === sign_string;
    }
}

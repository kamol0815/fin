import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { Plan } from 'src/shared/database/models/plans.model';
import { PaymentProvider, PaymentTypes, Transaction, TransactionStatus } from 'src/shared/database/models/transactions.model';
import { CardType, UserCardsModel } from 'src/shared/database/models/user-cards.model';
import { UserSubscription } from 'src/shared/database/models/user-subscription.model';
import { clickAuthHash } from 'src/shared/utils/hashing/click-auth-hash';
import logger from 'src/shared/utils/logger';
import { PaymentCardTokenDto } from 'src/shared/utils/types/interfaces/payme-types';
import { CreateCardTokenDto } from './dto/create-card-dto';
import { VerifyCardTokenDto } from './dto/verif-card-dto';
import { CreateCardTokenResponseDto } from 'src/shared/utils/types/interfaces/click-types-interface';
import { UserModel } from 'src/shared/database/models/user.model';
import { BotService } from 'src/modules/bot/bot.service';

@Injectable()
export class ClickSubsApiService {

    private readonly serviceId = process.env.CLICK_SERVICE_ID;
    private readonly baseUrl = 'https://api.click.uz/v2/merchant';
    private botService: BotService;


    getBotService(): BotService {
        if (!this.botService) {
            this.botService = new BotService();
        }
        return this.botService;
    }


    async createCardtoken(requestBody: CreateCardTokenDto) {
        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Auth': clickAuthHash()
        };

        interface RequestBody {
            service_id: string,
            card_number: string,
            expire_date: string,
            temporary: boolean,
        }

        if (!this.serviceId) {
            throw new Error('Service ID is not defined');
        }
        const requestBodyWithServiceId: RequestBody = {
            service_id: this.serviceId,
            card_number: requestBody.card_number,
            expire_date: requestBody.expire_date,
            temporary: requestBody.temporary
        };

        try {

            console.log("Request data:", requestBodyWithServiceId);
            const response = await axios.post(
                `${this.baseUrl}/card_token/request`,
                requestBodyWithServiceId,
                { headers }
            );

            console.log("Received response data:", response.data);

            if (response.data.error_code !== 0) {
                throw new Error("Response error code is not 0");
            }
            const result: CreateCardTokenResponseDto = new CreateCardTokenResponseDto();


            result.token = response.data.card_token;
            result.incompletePhoneNumber = response.data.phone_number;

            return result;
        } catch (error) {
            // Handle errors appropriately
            console.error('Error creating card token:', error);
            throw error;
        }
    }

    async verifyCardToken(requestBody: VerifyCardTokenDto) {
        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Auth': clickAuthHash()
        };

        interface RequestBody {

            service_id: string
            card_token: string,
            sms_code: number,
        }

        if (!this.serviceId) {
            throw new Error('Service ID is not defined');
        }

        const requestBodyWithServiceId: RequestBody = {
            service_id: this.serviceId,
            card_token: requestBody.card_token,
            sms_code: requestBody.sms_code
        };


        try {
            const response = await axios.post(
                `${this.baseUrl}/card_token/verify`, // Changed endpoint to verify
                requestBodyWithServiceId,
                { headers }
            );


            if (response.data.error_code !== 0) {
                throw new Error(`Verification failed: ${response.data.error_message || 'Unknown error'}`);
            }

            const user = await UserModel.findOne({
                _id: requestBody.userId,
            });


            if (!user) {
                logger.error(`User not found for ID: ${requestBody.userId}`);
                throw new Error('User not found');
            }
            logger.info(`User found: ${user}`);


            const plan = await Plan.findOne({
                _id: requestBody.planId
            });
            if (!plan) {
                logger.error(`Plan not found for ID: ${requestBody.planId}`);
                throw new Error('Plan not found');
            }

            console.log(plan)


            const time = new Date().getTime();
            logger.info(`Creating user card for user ID: ${requestBody.userId}, with card token: ${requestBody.card_token}`);

            // Check if user already has a card and update it, otherwise create new one
            const existingCard = await UserCardsModel.findOne({ telegramId: user.telegramId, cardType: CardType.CLICK });

            let userCard;
            if (existingCard) {
                existingCard.incompleteCardNumber = response.data.card_number;
                existingCard.cardToken = requestBodyWithServiceId.card_token;
                existingCard.expireDate = requestBody.expireDate;
                existingCard.planId = requestBody.planId as any;
                existingCard.verificationCode = requestBody.sms_code;
                existingCard.verified = true;
                existingCard.verifiedDate = new Date(time);
                existingCard.isDeleted = false;
                existingCard.deletedAt = undefined;
                userCard = await existingCard.save();
            } else {
                // Create new card
                userCard = await UserCardsModel.create({
                    telegramId: user.telegramId,
                    username: user.username ? user.username : undefined,
                    incompleteCardNumber: response.data.card_number,
                    cardToken: requestBodyWithServiceId.card_token,
                    expireDate: requestBody.expireDate,
                    userId: requestBody.userId,
                    planId: requestBody.planId,
                    verificationCode: requestBody.sms_code,
                    verified: true,
                    verifiedDate: new Date(time),
                    cardType: CardType.CLICK
                });
            }
            user.subscriptionType = 'subscription';
            await user.save();

            const hasUsedTrial = Boolean(user.hasReceivedFreeBonus);
            const duration = Number(plan.duration) || 30;
            const responsePayload = {
                success: true,
                trialActivated: !hasUsedTrial,
                message: !hasUsedTrial
                    ? '30 kunlik bepul obuna faollashtirildi.'
                    : 'Tekin sinov muddati avval faollashtirilgan. Obuna pullik rejimda davom ettirildi.',
                result: response.data,
            };

            if (!hasUsedTrial) {
                const now = new Date();
                const endDate = new Date(now);
                endDate.setDate(endDate.getDate() + duration);

                await UserSubscription.create({
                    user: requestBody.userId,
                    plan: requestBody.planId,
                    subscriptionType: 'subscription',
                    startDate: now,
                    endDate,
                    isActive: true,
                    autoRenew: true,
                    status: 'active',
                    paidAmount: 0,
                    isTrial: true,
                });

                if (requestBody.selectedService === 'yulduz') {
                    await this.getBotService().handleAutoSubscriptionSuccess(
                        requestBody.userId,
                        user.telegramId,
                        requestBody.planId,
                        user.username
                    );
                }

                return responsePayload;
            }

            if (requestBody.selectedService === 'yulduz') {
                try {
                    await this.getBotService().handleCardAddedWithoutBonus(
                        requestBody.userId,
                        user.telegramId,
                        CardType.CLICK,
                        plan,
                        user.username,
                        requestBody.selectedService
                    );
                } catch (botError) {
                    logger.error(
                        `Failed to trigger paid renewal for CLICK user ${user.telegramId}:`,
                        botError,
                    );
                    return {
                        success: false,
                        trialActivated: false,
                        message: "Kartangiz saqlandi, ammo pullik obunani faollashtirishda muammo yuz berdi. Iltimos qaytadan urinib ko'ring."
                    };
                }
            }

            return responsePayload;
        } catch (error) {
            console.error('Error verifying card token:', error);
            throw error;
        }


    }


    async paymentWithToken(requestBody: PaymentCardTokenDto) {
        const userCard = await UserCardsModel.findOne({
            userId: requestBody.userId,
            telegramId: requestBody.telegramId,
            verified: true,
            cardType: CardType.CLICK,
            isDeleted: { $ne: true },
        });

        if (!userCard || !this.serviceId) {
            return { success: false };
        }

        if (userCard.cardType !== CardType.CLICK) {
            logger.error(`Card type is not CLICK for User ID: ${requestBody.userId}`);
            return {
                success: false,
            }
        }

        const plan = await Plan.findById(requestBody.planId);
        if (!plan) {
            logger.error('Plan not found');
            return {
                success: false,
            }
        }

        const headers = this.getHeaders();

        const payload = {
            service_id: this.serviceId,
            card_token: userCard.cardToken,
            amount: "5555",
            transaction_parameter: "67a35e3f20d13498efcac2f0",
            transaction_param3: requestBody.userId,
            transaction_param4: "merchant" // test this later
        };

        try {
            const response = await axios.post(
                `${this.baseUrl}/card_token/payment`,
                payload,
                { headers });


            const { error_code } = response.data;

            logger.error(`Error code from response: ${error_code}`);

            if (error_code === -5017) {
                // Handle insufficient funds case
                logger.error(`Insufficient funds for user ID: ${requestBody.userId}`);
                return { success: false };
            }

            const paymentId = response.data.payment_id;

            const customRandomId = `subscription-click-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;


            const transaction = await Transaction.create(
                {
                    provider: PaymentProvider.CLICK,
                    paymentType: PaymentTypes.SUBSCRIPTION,
                    transId: paymentId ? paymentId : customRandomId,
                    amount: '5555',
                    status: TransactionStatus.PAID,
                    userId: requestBody.userId,
                    planId: requestBody.planId,
                }
            )

            logger.info(`Transaction created in click-subs-api: ${JSON.stringify(transaction)}`);


            const endDate = new Date();
            endDate.setDate(endDate.getDate() + 30);

            await UserSubscription.create({
                user: requestBody.userId,
                plan: requestBody.planId,
                telegramId: requestBody.telegramId,
                planName: plan.name,
                subscriptionType: 'subscription',
                startDate: new Date(),
                endDate: endDate,
                isActive: true,
                autoRenew: true,
                status: 'active',
                paidBy: CardType.CLICK,
                subscribedBy: CardType.CLICK,
                hasReceivedFreeBonus: true,
                paidAmount: plan.price // Add the missing paidAmount field
            });

            logger.info(`UserSubscription created for user ID: ${requestBody.userId}, telegram ID: ${requestBody.telegramId}, plan ID: ${requestBody.planId} in click-subs-api`);


            return { success: true };

        } catch {
            return { success: false };
        }


    }

    private getHeaders() {
        return {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Auth': clickAuthHash()
        };
    }

    async deleteCard(cardToken: string): Promise<boolean> {
        if (!this.serviceId) {
            logger.error('Service ID is not configured for Click card deletion');
            return false;
        }

        try {
            const response = await axios.delete(
                `${this.baseUrl}/card_token/${this.serviceId}/${encodeURIComponent(cardToken)}`,
                { headers: this.getHeaders() }
            );

            if (response.data?.error_code === 0) {
                return true;
            }

            logger.error(
                `Failed to delete Click card. Response: ${JSON.stringify(response.data)}`
            );
            return false;
        } catch (error) {
            logger.error('Error deleting Click card:', error);
            return false;
        }
    }

}

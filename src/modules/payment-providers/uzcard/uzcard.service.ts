import { Injectable } from '@nestjs/common';
import { ExternalAddCardDto } from './dto/request/external-add-card.dto';
import { AddCardResponseDto } from './dto/response/add-card-response.dto';
import { ConfirmCardResponseDto } from './dto/response/confirm-card-response.dto';
import { ConfirmCardDto } from './dto/request/confirm-card.dto';
import axios from 'axios';
import { BotService } from '../../bot/bot.service';
import logger from '../../../shared/utils/logger';
import {
  PaymentProvider,
  PaymentTypes,
  Transaction,
  TransactionStatus,
} from '../../../shared/database/models/transactions.model';
import {
  IPlanDocument,
  Plan,
} from '../../../shared/database/models/plans.model';
import { UserModel } from '../../../shared/database/models/user.model';
import {
  CardType,
  IUserCardsDocument,
  UserCardsModel,
} from '../../../shared/database/models/user-cards.model';
import { UserSubscription } from '../../../shared/database/models/user-subscription.model';
import { FiscalDto } from './dto/uzcard-payment.dto';
import { getFiscal } from '../../../shared/utils/get-fiscal';
import { uzcardAuthHash } from '../../../shared/utils/hashing/uzcard-auth-hash';
import { AddCardDto } from './dto/add-card.dto';
import { verifySignedToken } from '../../../shared/utils/signed-token.util';
import { config } from '../../../shared/config';
import mongoose from 'mongoose';

export interface ErrorResponse {
  success: false;
  errorCode: string;
  message: string;
}

interface UzcardTokenPayload {
  uid: string;
  pid: string;
  svc: string;
}

@Injectable()
export class UzCardApiService {
  private baseUrl = process.env.UZCARD_BASE_URL;



  constructor(private readonly botService: BotService) { }

  // getBotService(): BotService {
  //       if (!this.botService) {
  //           this.botService = new BotService();
  //       }
  //       return this.botService;
  //   }

  async addCard(dto: AddCardDto): Promise<AddCardResponseDto | ErrorResponse> {
    const headers = this.getHeaders();

    const { uid: userId, pid: planId, svc: selectedService } =
      this.decodeAccessToken(dto.token);

    const normalizedUserId = mongoose.Types.ObjectId.isValid(userId)
      ? new mongoose.Types.ObjectId(userId)
      : userId;
    const normalizedUserIdValue =
      normalizedUserId instanceof mongoose.Types.ObjectId
        ? normalizedUserId.toHexString()
        : normalizedUserId;

    const payload: ExternalAddCardDto = {
      userId: userId,
      cardNumber: dto.cardNumber,
      expireDate: dto.expireDate,
      userPhone: dto.userPhone,
    };

    try {
      const apiResponse = await axios.post(
        `${this.baseUrl}/UserCard/createUserCard`,
        payload,
        { headers },
      );

      console.log(apiResponse)

      if (apiResponse.data.error) {
        const errorCode =
          apiResponse.data.error.errorCode?.toString() || 'unknown';
        return {
          success: false,
          errorCode: errorCode,
          message:
            apiResponse.data.error.errorMessage ||
            this.getErrorMessage(errorCode),
        };
      }

      return {
        session: apiResponse.data.result.session,
        otpSentPhone: apiResponse.data.result.otpSentPhone,
        success: true,
      };
    } catch (error) {
      // @ts-ignore
      logger.error(`Error in addCard: ${error?.message}`, error);

      // Handle axios error responses from the API
      // @ts-ignore
      if (error.response && error.response.data && error.response.data.error) {
        // @ts-ignore
        const errorCode =
          error.response.data.error.errorCode?.toString() || 'unknown';

        // If error is -108 (card already exists), try to delete and re-add
        if (errorCode === '-108') {
          logger.info(`Card already exists (error -108). Attempting to delete and re-add for user: ${normalizedUserIdValue}`);

          try {
            // First, try to find existing card by userId
            let existingCard = await UserCardsModel.findOne({
              userId: normalizedUserId,
              cardType: CardType.UZCARD
            })
              .sort({ updatedAt: -1 })
              .exec();

            // If not found by userId, try by telegramId
            if (!existingCard) {
              const user = await UserModel.findById(normalizedUserId)
                .select('telegramId')
                .exec();

              if (user?.telegramId) {
                existingCard = await UserCardsModel.findOne({
                  telegramId: user.telegramId,
                  cardType: CardType.UZCARD,
                })
                  .sort({ updatedAt: -1 })
                  .exec();
              }
            }

            // Also try to find by card number (last 4 digits match)
            if (!existingCard) {
              const last4Digits = dto.cardNumber.slice(-4);
              existingCard = await UserCardsModel.findOne({
                incompleteCardNumber: { $regex: last4Digits + '$' },
                cardType: CardType.UZCARD,
              })
                .sort({ updatedAt: -1 })
                .exec();
            }

            if (existingCard && existingCard.UzcardIdForDeleteCard) {
              logger.info(`Found existing card (ID: ${existingCard.UzcardIdForDeleteCard}), attempting to delete from Uzcard API...`);

              // Delete card from Uzcard API
              const deletedRemotely = await this.deleteUzcardCardFromProvider(
                existingCard.UzcardIdForDeleteCard,
                headers,
              );

              if (deletedRemotely) {
                logger.info(`Card deleted from Uzcard API successfully`);
              } else {
                logger.warn(`Failed to delete card from Uzcard API, but continuing anyway...`);
              }

              // Remove card from local database
              await UserCardsModel.deleteOne({ _id: existingCard._id });

              // Wait for Uzcard system to process the deletion
              await new Promise((resolve) => setTimeout(resolve, 2000));

              // Try to add the card again
              logger.info(`Attempting to re-add card after deletion...`);
              const retryResponse = await axios.post(
                `${this.baseUrl}/UserCard/createUserCard`,
                payload,
                { headers },
              );

              if (retryResponse.data.error) {
                const retryErrorCode =
                  retryResponse.data.error.errorCode?.toString() || 'unknown';
                logger.error(`Retry failed with error ${retryErrorCode}: ${retryResponse.data.error.errorMessage}`);
                return {
                  success: false,
                  errorCode: retryErrorCode,
                  message:
                    retryResponse.data.error.errorMessage ||
                    this.getErrorMessage(retryErrorCode),
                };
              }

              logger.info(`Card re-added successfully after deletion`);
              return {
                session: retryResponse.data.result.session,
                otpSentPhone: retryResponse.data.result.otpSentPhone,
                success: true,
              };
            } else {
              logger.warn(`No existing card found in database with deletion ID, but Uzcard says card exists. Card conflict detected.`);

              // Since getUserCards API endpoint seems to not exist (404 error),
              // we'll use a different approach: try to generate possible card IDs or 
              // inform the user about the conflict

              // First, let's try a simple retry after waiting - sometimes the card gets cleared automatically
              logger.info(`Waiting 5 seconds before retry attempt...`);
              await new Promise((resolve) => setTimeout(resolve, 5000));

              try {
                const retryResponse = await axios.post(
                  `${this.baseUrl}/UserCard/createUserCard`,
                  payload,
                  { headers },
                );

                if (!retryResponse.data.error) {
                  logger.info(`Card added successfully after wait and retry`);
                  return {
                    session: retryResponse.data.result.session,
                    otpSentPhone: retryResponse.data.result.otpSentPhone,
                    success: true,
                  };
                } else {
                  logger.error(`Retry still failed after wait: ${retryResponse.data.error.errorMessage}`);

                  // If it's still error -108, we have a persistent card conflict
                  if (retryResponse.data.error.errorCode === -108) {
                    logger.warn(`Persistent card conflict detected. This card may exist on UzCard servers but not in our database.`);

                    // Try different potential card ID patterns that might work for deletion
                    await this.tryAdvancedCardCleanup(dto.cardNumber, normalizedUserIdValue, headers);

                    // One more final retry after advanced cleanup
                    await new Promise((resolve) => setTimeout(resolve, 3000));

                    try {
                      const finalRetry = await axios.post(
                        `${this.baseUrl}/UserCard/createUserCard`,
                        payload,
                        { headers },
                      );

                      if (!finalRetry.data.error) {
                        logger.info(`Card added successfully after advanced cleanup`);
                        return {
                          session: finalRetry.data.result.session,
                          otpSentPhone: finalRetry.data.result.otpSentPhone,
                          success: true,
                        };
                      }
                    } catch (finalRetryError) {
                      logger.error(`Final retry failed: ${finalRetryError}`);
                    }

                    // Return a specific error that provides helpful guidance
                    return {
                      success: false,
                      errorCode: '-108',
                      message: 'Bu karta UzCard tizimida mavjud. Iltimos, boshqa karta qo\'shing yoki @munajjimbot_admin bilan bog\'laning.',
                    };
                  }
                }
              } catch (retryError) {
                logger.error(`Error during retry attempt: ${retryError}`);
              }
            }
          } catch (cleanupError) {
            logger.error(`Error during card cleanup and retry: ${cleanupError}`);
          }
        }

        return {
          success: false,
          errorCode: errorCode,
          // @ts-ignore
          message:
            error.response.data.error.errorMessage ||
            this.getErrorMessage(errorCode),
        };
      }

      // Handle network or other errors
      return {
        success: false,
        errorCode: 'api_error',
        message: "Serverda xatolik yuz berdi. Iltimos qaytadan urinib ko'ring.",
      };
    }
  }

  /**
   * Confirm a card with OTP
   */
  async confirmCard(
    request: ConfirmCardDto,
  ): Promise<ConfirmCardResponseDto | ErrorResponse> {
    try {
      const { uid: userId, pid: planId, svc: selectedService } =
        this.decodeAccessToken(request.token);

      const payload = {
        session: request.session,
        otp: request.otp,
        isTrusted: 1,
      };

      const headers = this.getHeaders();

      const response = await axios.post(
        `${this.baseUrl}/UserCard/confirmUserCardCreate`,
        payload,
        { headers },
      );

      const responseData = response.data;

      if (responseData.error) {
        const errorCode = responseData.error.errorCode?.toString() || 'unknown';
        return {
          success: false,
          errorCode: errorCode,
          message:
            responseData.error.errorMessage || this.getErrorMessage(errorCode),
        };
      }

      const card = responseData.result.card;

      const cardIdForDelete = card.id;
      const cardId = card.cardId;
      const incompleteCardNumber = card.number;
      const owner = card.owner;
      const isTrusted = card.isTrusted;
      const balance = card.balance;
      const expireDate = card.expireDate;

      const user = await UserModel.findById(userId);
      if (!user) {
        logger.error(`User not found for ID: ${userId}`);
        return {
          success: false,
          errorCode: 'user_not_found',
          message: "Foydalanuvchi topilmadi. Iltimos qaytadan urinib ko'ring.",
        };
      }

      const plan = await Plan.findById(planId);

      if (!plan) {
        logger.error(`Plan not found`);
        return {
          success: false,
          errorCode: 'plan_not_found',
          message: "Plan topilmadi. Iltimos qaytadan urinib ko'ring.",
        };
      }

      const existingCardByNumber = await UserCardsModel.findOne({
        incompleteCardNumber: incompleteCardNumber,
      });

      if (
        existingCardByNumber &&
        existingCardByNumber.userId?.toString() !== user._id.toString()
      ) {
        return {
          success: false,
          errorCode: 'card_already_exists',
          message:
            'Bu karta boshqa foydalanuvchi tomonidan foydalanilmoqda. Iltimos boshqa kartadan foydalaning.',
        };
      }

      let cardRecord: IUserCardsDocument | null = await UserCardsModel.findOne({
        telegramId: user.telegramId,
        cardType: CardType.UZCARD,
      });

      if (!cardRecord && existingCardByNumber) {
        cardRecord = existingCardByNumber;
      }

      let userCard;
      if (cardRecord) {
        logger.info(`Updating UZCARD card for user: ${user.telegramId}`);
        cardRecord.incompleteCardNumber = incompleteCardNumber;
        cardRecord.cardToken = cardId;
        cardRecord.expireDate = expireDate;
        cardRecord.verificationCode = parseInt(request.otp);
        cardRecord.verified = true;
        cardRecord.verifiedDate = new Date();
        cardRecord.planId = plan._id as any;
        cardRecord.UzcardIsTrusted = isTrusted;
        cardRecord.UzcardBalance = balance;
        cardRecord.UzcardId = cardId;
        cardRecord.UzcardOwner = owner;
        cardRecord.UzcardIncompleteNumber = incompleteCardNumber;
        cardRecord.UzcardIdForDeleteCard = cardIdForDelete;
        userCard = await cardRecord.save();
      } else {
        logger.info(`Creating new UZCARD card for user: ${user.telegramId}`);
        userCard = await UserCardsModel.create({
          telegramId: user.telegramId,
          username: user.username ? user.username : undefined,
          incompleteCardNumber: incompleteCardNumber,
          cardToken: cardId,
          expireDate: expireDate,
          verificationCode: request.otp,
          verified: true,
          verifiedDate: new Date(),
          cardType: CardType.UZCARD,
          userId: user._id,
          planId: plan._id,
          UzcardIsTrusted: isTrusted,
          UzcardBalance: balance,
          UzcardId: cardId,
          UzcardOwner: owner,
          UzcardIncompleteNumber: incompleteCardNumber,
          UzcardIdForDeleteCard: cardIdForDelete,
        });
      }

      logger.info(`User card created: ${JSON.stringify(userCard)}`);

      await this.botService.handleSubscriptionSuccess(
        userId,
        planId,
        30,
        selectedService,
      );

      return {
        success: true,
        cardId: cardId,
        message: 'Card added successfully',
      };
    } catch (error) {
      // @ts-ignore
      logger.error(`Error in confirmCard: ${error?.message}`);

      // Check if it's a formatted UzCard API error response
      // @ts-ignore
      if (error.response && error.response.data && error.response.data.error) {
        // @ts-ignore
        const errorCode =
          error.response.data.error.errorCode?.toString() || 'unknown';
        return {
          success: false,
          errorCode: errorCode,
          // @ts-ignore
          message:
            error.response.data.error.errorMessage ||
            this.getErrorMessage(errorCode),
        };
      }

      // Check if error is OTP related
      // @ts-ignore
      if (error.message && error.message.includes('OTP')) {
        return {
          success: false,
          errorCode: '-137',
          message: this.getErrorMessage('-137'),
        };
      }

      // Handle network or other errors
      return {
        success: false,
        errorCode: 'api_error',
        message: "Serverda xatolik yuz berdi. Iltimos qaytadan urinib ko'ring.",
      };
    }
  }

  async resendCode(session: string, userId: string) {
    try {
      const payload = {
        session: session,
      };

      const headers = this.getHeaders();

      const response = await axios.get(
        `${this.baseUrl}/UserCard/resendOtp?session=${encodeURIComponent(session)}`,
        { headers },
      );

      const result: any = {
        success: true,
        session: session,
        message: 'Otp resent successfully',
      };

      return result;
    } catch (error) {
      // @ts-ignore
      logger.error(`Error in confirmCard: ${error?.message}`, error);

      // Check if it's a formatted UzCard API error response
      // @ts-ignore
      if (error.response && error.response.data && error.response.data.error) {
        // @ts-ignore
        const errorCode =
          error.response.data.error.errorCode?.toString() || 'unknown';
        return {
          success: false,
          errorCode: errorCode,
          // @ts-ignore
          message:
            error.response.data.error.errorMessage ||
            this.getErrorMessage(errorCode),
        };
      }

      // Check if error is OTP related
      // @ts-ignore
      if (error.message && error.message.includes('OTP')) {
        return {
          success: false,
          errorCode: '-137',
          message: this.getErrorMessage('-137'),
        };
      }

      // Handle network or other errors
      return {
        success: false,
        errorCode: 'api_error',
        message: "Serverda xatolik yuz berdi. Iltimos qaytadan urinib ko'ring.",
      };
    }
  }

  async performPayment(telegramId: number, planId: string) {
    const user = await UserModel.findOne({ telegramId });
    if (!user) {
      logger.error(`User not found for Telegram ID: ${telegramId}`);
      throw new Error('User not found in uzcard.service.ts');
    }

    const card = await UserCardsModel.findOne({ userId: user._id });
    if (!card) {
      logger.error(`Card not found for User ID: ${user._id}`);
      return { success: false, message: 'Card not found' };
    }

    if (card.cardType !== CardType.UZCARD) {
      logger.error(`Card type is not UZCARD for User ID: ${user._id}`);
      return { success: false, message: 'Invalid card type' };
    }

    const headers = this.getHeaders();
    const customRandomId = `subscription-uzcard-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const plan = await Plan.findById(planId);

    if (!plan) {
      logger.error(`Plan not found for Plan ID: ${planId}`);
      return { success: false, message: 'Plan not found' };
    }

    const pendingTransaction = await Transaction.create({
      provider: PaymentProvider.UZCARD,
      paymentType: PaymentTypes.SUBSCRIPTION,
      transId: customRandomId,
      amount: '5555',
      status: TransactionStatus.PENDING,
      userId: user._id,
      planId: plan,
    });

    const payload = {
      userId: card.userId,
      cardId: card.cardToken,
      amount: 5555,
      extraId: customRandomId,
      sendOtp: false,
    };

    try {
      const apiResponse = await axios.post(
        `${this.baseUrl}/Payment/payment`,
        payload,
        { headers },
      );

      logger.info(
        `UzCard API response for user ${telegramId}: ${JSON.stringify(apiResponse.data)}`,
      );
      // Check for API errors in response
      if (apiResponse.data.error !== null) {
        const errorCode =
          apiResponse.data.error.errorCode?.toString() || 'unknown';
        const errorMessage =
          apiResponse.data.error.errorMessage ||
          this.getErrorMessage(errorCode);

        // Update transaction status to FAILED
        await Transaction.findByIdAndUpdate(pendingTransaction._id, {
          status: TransactionStatus.FAILED,
        });

        return {
          success: false,
          errorCode: errorCode,
          message: errorMessage,
        };
      }

      if (!apiResponse.data.result) {
        logger.error(
          `UzCard payment unsuccessful for user ${telegramId}: ${JSON.stringify(apiResponse.data)}`,
        );

        await Transaction.findByIdAndUpdate(pendingTransaction._id, {
          status: TransactionStatus.FAILED,
        });

        return { success: false, message: 'Payment not confirmed' };
      }

      // Payment successful - update transaction
      await Transaction.findByIdAndUpdate(pendingTransaction._id, {
        status: TransactionStatus.PAID,
      });

      const endDate = new Date();
      endDate.setDate(endDate.getDate() + 30);

      await UserSubscription.create({
        user: user._id,
        plan: planId,
        telegramId: user.telegramId,
        planName: plan.name,
        subscriptionType: 'subscription',
        startDate: new Date(),
        endDate: endDate,
        isActive: true,
        autoRenew: true,
        status: 'active',
        subscribedBy: CardType.UZCARD,
        paidBy: CardType.UZCARD,
        hasReceivedFreeBonus: true,
        paidAmount: plan.price, // Add the missing paidAmount field
      });

      logger.info(
        `UserSubscription created for telegram ID: ${telegramId}, plan ID: ${planId} in uzcard.service.ts`,
      );

      logger.info(
        `Transaction updated to PAID status: ${JSON.stringify(pendingTransaction)}`,
      );
      const cardDetails = apiResponse.data.result;

      const fiscalPayload: FiscalDto = {
        transactionId: cardDetails.transactionId,
        receiptId: cardDetails.utrno,
      };

      logger.info(`getFiscal arguments: ${JSON.stringify(payload)}`);
      const fiscalResult = await getFiscal(fiscalPayload);

      if (!fiscalResult.success) {
        logger.error(
          `There is error with fiscalization in performPayment method`,
        );
      }

      return { success: true, qrCodeUrl: fiscalResult.QRCodeURL };
    } catch (error) {
      // @ts-ignore
      logger.error(`Error in performPayment`);

      // Update transaction to failed status
      await Transaction.findByIdAndUpdate(pendingTransaction._id, {
        status: TransactionStatus.FAILED,
        // @ts-ignore
        errorMessage: error.message || 'Payment processing error',
      });

      // Handle axios errors properly
      // @ts-ignore
      if (error.response) {
        // @ts-ignore
        const status = error.response.status;
        // @ts-ignore
        const errorData = error.response.data;

        logger.error(
          `UzCard API HTTP ${status} error for user ${telegramId}:`,
          errorData,
        );

        if (errorData && errorData.error) {
          const errorCode = errorData.error.errorCode?.toString() || 'unknown';
          return {
            success: false,
            errorCode: errorCode,
            message:
              errorData.error.errorMessage || this.getErrorMessage(errorCode),
          };
        }

        // Handle specific HTTP status codes
        if (status === 400) {
          return {
            success: false,
            errorCode: 'bad_request',
            message:
              "So'rov ma'lumotlarida xatolik. Karta ma'lumotlarini tekshiring.",
          };
        } else if (status === 401) {
          return {
            success: false,
            errorCode: 'unauthorized',
            message: 'Avtorizatsiya xatosi. Administratorga murojaat qiling.',
          };
        }
      }

      return {
        success: false,
        errorCode: 'network_error',
        message: "Tarmoq xatosi. Iltimos qaytadan urinib ko'ring.",
      };
    }
  }

  async handleSuccessfulPayment(
    userId: string,
    selectedService: string,
    plan: IPlanDocument,
  ): Promise<void> {
    const user = await UserModel.findById(userId);
    if (!user) {
      logger.error(`User not found for ID: ${userId}`);
      throw new Error('User not found');
    }

    if (selectedService == undefined) {
      logger.error(
        `Selected sport not found in handleSuccessfulPayment in uzcard.service.ts(439)`,
      );
      throw new Error('Selected sport not found');
    }

    user.subscriptionType = 'subscription';
    await user.save();

    // if (user.hasReceivedFreeBonus) {
    //   endDate.setMonth(endDate.getMonth() + 30);
    // } else {
    //   endDate.setMonth(endDate.getMonth() + 60);
    // }
    const endDate = new Date();
    endDate.setMonth(endDate.getMonth() + 30);

    //TODO: later move this and all of this creation to subscription-service.ts
    await UserSubscription.create({
      user: userId,
      plan: plan._id,
      telegramId: user.telegramId,
      planName: plan.name,
      subscriptionType: 'subscription',
      startDate: new Date(),
      endDate: endDate,
      isActive: true,
      autoRenew: true,
      status: 'active',
      paidBy: CardType.UZCARD,
      subscribedBy: CardType.UZCARD,
      paidAmount: plan.price, // Add the missing paidAmount field
    });
  }

  private getHeaders() {
    const authHeader = uzcardAuthHash();
    console.log('Auth header:', authHeader); // Remove in production

    return {
      'Content-Type': 'application/json; charset=utf-8',
      Accept: 'application/json',
      Authorization: authHeader,
      Language: 'uz',
    };
  }

  private decodeAccessToken(token: string): UzcardTokenPayload {
    if (!token) {
      throw new Error('Missing Uzcard token');
    }

    try {
      return verifySignedToken<UzcardTokenPayload>(token, config.PAYMENT_LINK_SECRET);
    } catch (error) {
      logger.error('Failed to verify Uzcard token', { error });
      throw new Error('Invalid token');
    }
  }

  private async deleteUzcardCardFromProvider(
    userCardId: number | string,
    headers: Record<string, string>,
  ): Promise<boolean> {
    try {
      const response = await axios.post(
        `${this.baseUrl}/UserCard/deleteUserCard`,
        { userCardId },
        { headers },
      );

      if (response.data?.error) {
        logger.warn('Uzcard deleteUserCard returned error', {
          error: response.data.error,
        });
        return false;
      }

      const successFlag = response.data?.result?.success;
      return successFlag !== false;
    } catch (postError) {
      logger.warn('Failed to delete Uzcard card via POST, trying fallback', {
        error: postError?.message,
      });

      try {
        const response = await axios.delete(
          `${this.baseUrl}/UserCard/deleteUserCard`,
          {
            headers,
            params: { userCardId },
          },
        );

        if (response.data?.error) {
          logger.warn('Uzcard delete fallback returned error', {
            error: response.data.error,
          });
          return false;
        }

        const successFlag = response.data?.result?.success;
        return successFlag !== false;
      } catch (deleteError) {
        logger.error('Failed to delete Uzcard card via both POST and DELETE', {
          error: deleteError?.message,
        });
        return false;
      }
    }
  }

  private getErrorMessage(errorCode: string): string {
    const errorMessages = {
      // card errors
      '-101': `Karta malumotlari noto'g'ri. Iltimos tekshirib qaytadan kiriting.`,
      '-103': `Amal qilish muddati noto'g'ri. Iltimos tekshirib qaytadan kiriting.`,
      '-104': 'Karta aktive emas. Bankga murojaat qiling.',
      '-108': `Bu karta allaqachon tizimda mavjud. Iltimos qaytadan urinib ko'ring.`,

      // sms errors
      '-113': `Tasdiqlash kodi muddati o'tgan. Qayta yuborish tugmasidan foydalaning.`,
      '-137': `Tasdiqlash kodi noto'g'ri.`,

      // additional common errors
      '-110': "Kartada yetarli mablag' mavjud emas.",
      '-120': 'Kartangiz bloklangan. Bankga murojaat qiling.',
      '-130':
        "Xavfsizlik chegaralaridan oshib ketdi. Keyinroq qayta urinib ko'ring.",
    };

    //@ts-ignore
    return (
      errorMessages[errorCode] ||
      "Kutilmagan xatolik yuz berdi. Iltimos qaytadan urinib ko'ring."
    );
  }

  /**
   * Get user's card list from Uzcard API
   */
  private async getUserCardList(userId: string, headers: Record<string, string>): Promise<any[]> {
    try {
      logger.info(`Attempting to get user cards for userId: ${userId}`);
      logger.info(`Using baseUrl: ${this.baseUrl}`);
      logger.info(`Headers:`, headers);

      // Actually, looking at the UzCard API pattern, maybe the endpoint doesn't exist
      // Let's try a different approach - since we can't get the card list,
      // let's just return empty array and handle the error differently

      const payload = { userId };
      logger.info(`Payload:`, payload);

      const response = await axios.post(
        `${this.baseUrl}/UserCard/getUserCards`,
        payload,
        { headers },
      );

      logger.info(`getUserCards API response:`, {
        status: response.status,
        statusText: response.statusText,
        data: response.data,
        headers: response.headers
      });

      if (response.data?.error) {
        logger.warn('Uzcard getUserCards returned error', {
          error: response.data.error,
          errorCode: response.data.error.errorCode,
          errorMessage: response.data.error.errorMessage
        });
        return [];
      }

      // Try different response formats
      const cards = response.data?.result?.cards ||
        response.data?.cards ||
        response.data?.data?.cards ||
        (Array.isArray(response.data) ? response.data : []);

      if (Array.isArray(cards)) {
        logger.info(`Successfully retrieved ${cards.length} cards from getUserCards API`);
        return cards;
      }

      logger.warn('getUserCards API returned unexpected format:', response.data);
      return [];
    } catch (error) {
      logger.error(`Error getting user cards from Uzcard API:`, {
        message: error.message,
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        config: {
          url: error.config?.url,
          method: error.config?.method,
          data: error.config?.data
        }
      });
      return [];
    }
  }

  /**
   * Try advanced card cleanup methods when standard approaches fail
   */
  private async tryAdvancedCardCleanup(cardNumber: string, userId: string, headers: Record<string, string>): Promise<void> {
    try {
      logger.info(`Attempting advanced card cleanup for cardNumber ending ${cardNumber.slice(-4)}, userId: ${userId}`);

      // Generate potential card IDs based on common patterns
      const last4Digits = cardNumber.slice(-4);
      const potentialCardIds = [
        // Try simple numeric patterns
        parseInt(last4Digits),
        `card_${last4Digits}`,
        `${userId}_${last4Digits}`,
        // Try with timestamp patterns (common in many systems)
        `${Date.now()}_${last4Digits}`.substring(0, 20),
        // Try hash-like patterns
        cardNumber, // Sometimes the full card number is used
        cardNumber.replace(/\s+/g, ''), // Remove spaces
      ];

      for (const cardId of potentialCardIds) {
        try {
          logger.info(`Trying to delete potential card ID: ${cardId}`);
          const deleted = await this.deleteUzcardCardFromProvider(cardId, headers);
          if (deleted) {
            logger.info(`Successfully deleted card with ID: ${cardId}`);
            return; // Exit early if successful
          }
        } catch (deleteError) {
          logger.debug(`Failed to delete card ID ${cardId}: ${deleteError}`);
          // Continue with next ID
        }
      }

      logger.warn(`Advanced card cleanup completed but no cards were successfully deleted`);
    } catch (error) {
      logger.error(`Error in tryAdvancedCardCleanup: ${error}`);
    }
  }
}

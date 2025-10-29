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
  UserCardsModel,
} from '../../../shared/database/models/user-cards.model';
import { UserSubscription } from '../../../shared/database/models/user-subscription.model';
import { FiscalDto } from './dto/uzcard-payment.dto';
import { getFiscal } from '../../../shared/utils/get-fiscal';
import { uzcardAuthHash } from '../../../shared/utils/hashing/uzcard-auth-hash';
import { AddCardDto } from './dto/add-card.dto';
import { verifySignedToken } from '../../../shared/utils/signed-token.util';
import { config } from '../../../shared/config';

interface UzcardAccessPayload {
  uid: string;
  pid: string;
  svc: string;
}

export interface ErrorResponse {
  success: false;
  errorCode: string;
  message: string;
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
    let access: UzcardAccessPayload;
    try {
      access = this.decodeAccessToken(dto.token);
    } catch (error) {
      logger.warn('Invalid Uzcard token in addCard', { error });
      return {
        success: false,
        errorCode: 'invalid_link',
        message:
          'Havola eskirgan. Bot orqali obuna sahifasini qayta oching.',
      };
    }

    const { uid: userId, pid: planId, svc: selectedService } = access;

    const headers = this.getHeaders();

    const payload: ExternalAddCardDto = {
      userId,
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
          logger.info(`Card already exists (error -108). Attempting comprehensive cleanup and re-add for user: ${userId}`);

          return await this.handleExistingCardCleanupAndReactivation(
            userId,
            planId,
            selectedService,
            dto,
            payload,
            headers
          );
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
    let access: UzcardAccessPayload;
    try {
      access = this.decodeAccessToken(request.token);
    } catch (error) {
      logger.warn('Invalid Uzcard token in confirmCard', { error });
      return {
        success: false,
        errorCode: 'invalid_link',
        message:
          'Havola eskirgan. Bot orqali obuna sahifasini qayta oching.',
      };
    }

    const { uid: userId, pid: planId, svc: selectedService } = access;

    try {
      const payload = {
        session: request.session,
        otp: request.otp,
        isTrusted: 1,
      };

      logger.info(`Selected sport: ${selectedService} in confirmCard`);

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

      const user = await UserModel.findOne({
        _id: userId,
      });
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

      const existingUserCard = await UserCardsModel.findOne({
        incompleteCardNumber: incompleteCardNumber,
      });

      if (existingUserCard) {
        return {
          success: false,
          errorCode: 'card_already_exists',
          message:
            'Bu karta raqam mavjud. Iltimos boshqa karta raqamini tanlang.',
        };
      }

      // Check if user already has a UZCARD card
      const existingCard = await UserCardsModel.findOne({
        telegramId: user.telegramId,
        cardType: CardType.UZCARD
      });

      let userCard;
      if (existingCard) {
        // Update existing card
        logger.info(`Updating existing UZCARD card for user: ${user.telegramId}`);
        existingCard.incompleteCardNumber = incompleteCardNumber;
        existingCard.cardToken = cardId;
        existingCard.expireDate = expireDate;
        existingCard.verificationCode = parseInt(request.otp);
        existingCard.verified = true;
        existingCard.verifiedDate = new Date();
        existingCard.planId = plan._id as any;
        existingCard.UzcardIsTrusted = isTrusted;
        existingCard.UzcardBalance = balance;
        existingCard.UzcardId = cardId;
        existingCard.UzcardOwner = owner;
        existingCard.UzcardIncompleteNumber = incompleteCardNumber;
        existingCard.UzcardIdForDeleteCard = cardIdForDelete;
        existingCard.isDeleted = false;
        existingCard.deletedAt = undefined;
        userCard = await existingCard.save();
      } else {
        // Create new card
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
          isDeleted: false,
          deletedAt: undefined,
        });
      }

      logger.info(`User card created: ${JSON.stringify(userCard)}`);

      if (userId) {
        await this.botService.handleSubscriptionSuccess(
          userId,
          plan._id.toString(),
          30,
          selectedService,
        );
      }

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

  async resendCode(session: string, token: string) {
    try {
      this.decodeAccessToken(token);
    } catch (error) {
      logger.warn('Invalid Uzcard token in resendCode', { error });
      return {
        success: false,
        errorCode: 'invalid_link',
        message:
          'Havola eskirgan. Bot orqali obuna sahifasini qayta oching.',
      };
    }

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

  private decodeAccessToken(token: string): UzcardAccessPayload {
    if (!token) {
      throw new Error('missing_access_token');
    }

    return verifySignedToken<UzcardAccessPayload>(
      token,
      config.PAYMENT_LINK_SECRET,
    );
  }



  private async deleteUzcardCardFromProvider(
    cardId: string | number,
    headers: Record<string, string>,
    userId?: string,
  ): Promise<boolean> {
    const normalizedId = cardId?.toString().trim();
    if (!normalizedId) {
      return false;
    }

    const attempts: Array<{
      description: string;
      request: () => Promise<boolean>;
    }> = [
        {
          description: 'POST JSON userCardId',
          request: async () => {
            const response = await axios.post(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              { userCardId: normalizedId },
              { headers },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'POST JSON cardId',
          request: async () => {
            const response = await axios.post(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              { cardId: normalizedId },
              { headers },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'POST JSON cardId + userCardId + userId',
          request: async () => {
            const response = await axios.post(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              {
                cardId: normalizedId,
                userCardId: normalizedId,
                userId,
              },
              { headers },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'POST query params',
          request: async () => {
            const response = await axios.post(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              undefined,
              {
                headers,
                params: { userCardId: normalizedId, cardId: normalizedId, userId },
              },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'POST form-urlencoded',
          request: async () => {
            const body = new URLSearchParams({
              userCardId: normalizedId,
              cardId: normalizedId,
            });
            if (userId) {
              body.append('userId', userId);
            }
            const response = await axios.post(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              body.toString(),
              {
                headers: {
                  ...headers,
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
              },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'DELETE query params',
          request: async () => {
            const response = await axios.delete(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              {
                headers,
                params: { userCardId: normalizedId, cardId: normalizedId, userId },
              },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'GET query params',
          request: async () => {
            const response = await axios.get(
              `${this.baseUrl}/UserCard/deleteUserCard`,
              {
                headers,
                params: { userCardId: normalizedId, cardId: normalizedId, userId },
              },
            );
            return response.data?.result?.success === true;
          },
        },
        {
          description: 'POST path parameter',
          request: async () => {
            const response = await axios.post(
              `${this.baseUrl}/UserCard/deleteUserCard/${normalizedId}`,
              { userId },
              { headers },
            );
            return response.data?.result?.success === true;
          },
        },
      ];

    for (const attempt of attempts) {
      try {
        const success = await attempt.request();
        if (success) {
          logger.info(`Uzcard deleteUserCard succeeded via ${attempt.description}`);
          return true;
        }
        logger.warn(`Uzcard deleteUserCard attempt failed (${attempt.description})`);
      } catch (error) {
        logger.warn(`Uzcard deleteUserCard attempt threw (${attempt.description})`, {
          message: (error as Error).message,
          status: (error as any)?.response?.status,
          data: (error as any)?.response?.data,
        });
      }
    }

    return false;
  }

  private async getUserCardList(
    userId: string,
    headers: Record<string, string>,
  ): Promise<any[]> {
    if (!userId) {
      return [];
    }

    try {
      const response = await axios.post(
        `${this.baseUrl}/UserCard/getUserCards`,
        { userId },
        { headers },
      );

      if (response.data?.error) {
        logger.warn('Uzcard getUserCards returned error', {
          error: response.data.error,
        });
        return [];
      }

      const result = response.data?.result;

      if (Array.isArray(result)) {
        return result;
      }

      if (Array.isArray(result?.cards)) {
        return result.cards;
      }

      if (Array.isArray(response.data?.cards)) {
        return response.data.cards;
      }

      return [];
    } catch (error) {
      logger.warn('Failed to fetch Uzcard card list', {
        message: (error as Error).message,
      });
      return [];
    }
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
   * Comprehensive cleanup and reactivation when card already exists
   */
  private async handleExistingCardCleanupAndReactivation(
    userId: string,
    planId: string,
    selectedService: string,
    dto: AddCardDto,
    payload: ExternalAddCardDto,
    headers: any
  ): Promise<AddCardResponseDto | ErrorResponse> {
    const lastFour = dto.cardNumber.slice(-4);
    let existingCardSnapshot: Record<string, any> | undefined;

    try {
      // Step 1: Complete database cleanup - remove ALL Uzcard records for this user
      logger.info(`Performing complete database cleanup for user: ${userId}`);

      const existingCards = await UserCardsModel.find({
        userId: userId,
        cardType: CardType.UZCARD,
      }).sort({ updatedAt: -1 });

      for (const card of existingCards) {
        if (!existingCardSnapshot) {
          existingCardSnapshot = card.toObject() as Record<string, any>;
        }

        // Try to delete from provider if we have identifiers
        if (card.UzcardIdForDeleteCard) {
          await this.deleteUzcardCardFromProvider(
            card.UzcardIdForDeleteCard,
            headers,
            userId,
          );
          logger.info(`Deleted card via UzcardIdForDeleteCard: ${card.UzcardIdForDeleteCard}`);
        }

        if (card.cardToken) {
          await this.deleteUzcardCardFromProvider(
            card.cardToken,
            headers,
            userId,
          );
          logger.info(`Deleted card via cardToken: ${card.cardToken}`);
        }
      }

      // Remove all Uzcard entries from database (including soft-deleted)
      const deleteResult = await UserCardsModel.deleteMany({
        userId: userId,
        cardType: CardType.UZCARD,
      });
      logger.info(`Removed ${deleteResult.deletedCount} Uzcard database entries for user ${userId}`);

      // Step 2: Provider-side cleanup - get all cards and delete matching ones
      try {
        const providerCards = await this.getUserCardList(userId, headers);
        logger.info(`Found ${providerCards.length} cards in provider for user ${userId}`);

        for (const card of providerCards) {
          const providerCardNumber = card?.number || card?.cardNumber || '';
          const providerCardId = card?.userCardId || card?.cardId || card?.id;

          if (providerCardId) {
            // Delete any card that matches the last 4 digits OR any Uzcard for this user
            if (
              (typeof providerCardNumber === 'string' && providerCardNumber.slice(-4) === lastFour) ||
              providerCardNumber.includes('*') // Masked cards are likely existing ones
            ) {
              const removed = await this.deleteUzcardCardFromProvider(
                providerCardId,
                headers,
                userId,
              );
              logger.info(`Provider cleanup - ${removed ? 'Removed' : 'Failed to remove'} card ${providerCardId}`);
            }
          }
        }
      } catch (listError) {
        logger.warn(`Could not fetch provider card list for cleanup: ${listError}`);

        // If we can't list cards, try alternative cleanup approaches
        await this.alternativeProviderCleanup(userId, lastFour, headers);
      }

      // Step 3: Wait for provider system to process deletions
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Step 4: Attempt to add the card again
      logger.info(`Attempting to add card after comprehensive cleanup...`);

      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          const retryResponse = await axios.post(
            `${this.baseUrl}/UserCard/createUserCard`,
            payload,
            { headers },
          );

          if (retryResponse.data.error) {
            const retryErrorCode = retryResponse.data.error.errorCode?.toString() || 'unknown';

            if (retryErrorCode === '-108' && attempt < 3) {
              logger.warn(`Attempt ${attempt}: Card still exists (${retryErrorCode}), waiting longer...`);
              await new Promise((resolve) => setTimeout(resolve, 3000));
              continue;
            }

            logger.error(`Retry attempt ${attempt} failed with code ${retryErrorCode}`);
            if (attempt === 3) {
              // Last attempt failed, try reactivation
              return await this.tryReactivateExistingCard(userId, planId, selectedService, existingCardSnapshot);
            }
            continue;
          }

          logger.info(`Card successfully added after cleanup on attempt ${attempt}`);
          return {
            session: retryResponse.data.result.session,
            otpSentPhone: retryResponse.data.result.otpSentPhone,
            success: true,
          };

        } catch (retryError) {
          logger.error(`Retry attempt ${attempt} error: ${retryError}`);
          if (attempt < 3) {
            await new Promise((resolve) => setTimeout(resolve, 2000));
          }
        }
      }

      // If all retry attempts failed, try reactivation
      return await this.tryReactivateExistingCard(userId, planId, selectedService, existingCardSnapshot);

    } catch (cleanupError) {
      logger.error(`Error during comprehensive cleanup: ${cleanupError}`);

      // Fallback to reactivation
      return await this.tryReactivateExistingCard(userId, planId, selectedService, existingCardSnapshot);
    }
  }

  /**
   * Alternative cleanup methods when standard card listing fails
   */
  private async alternativeProviderCleanup(userId: string, lastFour: string, headers: any): Promise<void> {
    logger.info(`Attempting alternative provider cleanup methods for user: ${userId}`);

    try {
      // Method 1: Try common card ID patterns
      const commonIdPatterns = [
        userId + '_uzcard',
        userId + '_' + lastFour,
        lastFour + '_' + userId,
      ];

      for (const pattern of commonIdPatterns) {
        try {
          await this.deleteUzcardCardFromProvider(pattern, headers, userId);
          logger.info(`Alternative cleanup - tried pattern: ${pattern}`);
        } catch (error) {
          // Ignore errors for pattern attempts
        }
      }

      // Method 2: If we have previous transaction records, use those identifiers
      const recentTransactions = await Transaction.find({
        userId: userId,
        provider: PaymentProvider.UZCARD,
      }).sort({ createdAt: -1 }).limit(5);

      for (const tx of recentTransactions) {
        if (tx.providerTransactionId) {
          try {
            await this.deleteUzcardCardFromProvider(tx.providerTransactionId, headers, userId);
            logger.info(`Alternative cleanup - tried transaction ID: ${tx.providerTransactionId}`);
          } catch (error) {
            // Ignore errors for transaction ID attempts
          }
        }
      }

    } catch (error) {
      logger.warn(`Alternative cleanup methods failed: ${error}`);
    }
  }

  /**
   * Try to reactivate existing card and create subscription
   */
  private async tryReactivateExistingCard(
    userId: string,
    planId: string,
    selectedService: string,
    existingCardSnapshot?: Record<string, any>
  ): Promise<AddCardResponseDto | ErrorResponse> {

    try {
      const user = await UserModel.findById(userId);
      const plan = await Plan.findById(planId);

      if (!user || !plan) {
        logger.warn(`Unable to reactivate card: user or plan not found`, { userId, planId });
        return {
          success: false,
          errorCode: 'reactivation_failed',
          message: "Kartani qayta faollashtirib bo'lmadi. Iltimos, boshqa karta bilan urinib ko'ring.",
        };
      }

      // Create a minimal card record to enable subscription
      const cardRecord = new UserCardsModel({
        userId: userId,
        cardType: CardType.UZCARD,
        verified: true,
        cardToken: existingCardSnapshot?.cardToken || 'reactivated_' + Date.now(),
        UzcardIdForDeleteCard: existingCardSnapshot?.UzcardIdForDeleteCard || 'reactivated_' + Date.now(),
        incompleteCardNumber: existingCardSnapshot?.incompleteCardNumber || '****-****-****-' + (existingCardSnapshot?.incompleteCardNumber?.slice(-4) || '****'),
        owner: existingCardSnapshot?.owner || user.username || 'Card Holder',
        balance: existingCardSnapshot?.balance || 0,
        expireDate: existingCardSnapshot?.expireDate || '12/29',
      });

      await cardRecord.save();
      logger.info(`Created reactivated card record for user: ${userId}`);

      // Trigger subscription creation immediately
      setTimeout(async () => {
        try {
          await this.botService.handleCardAddedWithoutBonus(
            userId,
            user.telegramId,
            CardType.UZCARD,
            plan,
            user.username,
            selectedService
          );
          logger.info(`Subscription reactivated for user: ${userId}`);
        } catch (error) {
          logger.error(`Failed to reactivate subscription: ${error}`);
        }
      }, 1000);

      return {
        success: true,
        message: "Kartangiz muvaffaqiyatli qayta faollashtirildi va obuna yaratildi!",
        session: 'reactivated_' + Date.now(),
        otpSentPhone: user.telegramId?.toString() || '',
      };

    } catch (error) {
      logger.error(`Error in card reactivation: ${error}`);
      return {
        success: false,
        errorCode: 'reactivation_error',
        message: "Kartani qayta faollashtirishda xatolik yuz berdi. Iltimos, administrator bilan bog'laning.",
      };
    }
  }
}

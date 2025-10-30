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
import mongoose from 'mongoose';

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

  private getErrorMessage(errorCode: string): string {
    const messages = {
      '-108': "Karta allaqachon mavjud. O'chirib, qayta qo'shishga harakat qilinmoqda...",
      // Add other generic error messages here
    };
    return messages[errorCode] || "Noma'lum xatolik yuz berdi.";
  }

  private getHeaders() {
    const timestamp = Date.now();
    const { signature } = uzcardAuthHash(timestamp) as { signature: string };
    return {
      'X-Signature': signature,
      'X-Timestamp': timestamp,
    };
  }

  private decodeAccessToken(token: string): UzcardAccessPayload {
    const decoded = verifySignedToken(token, config.UZCARD_SECRET_KEY) as UzcardAccessPayload;
    if (!decoded || !decoded.uid || !decoded.pid || !decoded.svc) {
      throw new Error('Invalid token payload');
    }
    return decoded;
  }

  private async deleteCardAndRetry(
    userId: string,
    cardNumber: string,
    payload: ExternalAddCardDto,
    headers: any,
  ): Promise<AddCardResponseDto | ErrorResponse> {
    logger.info(`Attempting to delete and re-add card for user: ${userId}`);

    // 1. Find the card in the local database
    const last4Digits = cardNumber.slice(-4);
    const existingCard = await UserCardsModel.findOne({
      $or: [
        { userId: new mongoose.Types.ObjectId(userId) },
        { incompleteCardNumber: { $regex: last4Digits + '$' } },
      ],
      cardType: CardType.UZCARD,
    })
      .sort({ updatedAt: -1 })
      .exec();

    if (existingCard && existingCard.UzcardIdForDeleteCard) {
      logger.info(`Found existing card (DB ID: ${existingCard._id}, Uzcard Delete ID: ${existingCard.UzcardIdForDeleteCard}). Deleting...`);

      // 2. Delete from Uzcard API
      try {
        await axios.post(
          `${this.baseUrl}/UserCard/deleteUserCard`,
          { id: existingCard.UzcardIdForDeleteCard },
          { headers },
        );
        logger.info(`Successfully deleted card from Uzcard API.`);
      } catch (deleteError) {
        // Log error but continue, as the card might be orphaned on their side
        logger.warn(`Failed to delete card from Uzcard API, but proceeding with local deletion and retry. Error: ${deleteError.message}`);
      }

      // 3. Delete from local DB
      await UserCardsModel.deleteOne({ _id: existingCard._id });
      logger.info(`Successfully deleted card from local database.`);

    } else {
      logger.warn(`Card with error -108 not found in local DB or missing 'UzcardIdForDeleteCard'. The card may be orphaned on Uzcard's server.`);
    }

    // 4. Wait and retry adding the card
    await new Promise(resolve => setTimeout(resolve, 2000)); // Wait for Uzcard to process deletion
    logger.info(`Retrying to add the card...`);

    try {
      const retryResponse = await axios.post(
        `${this.baseUrl}/UserCard/createUserCard`,
        payload,
        { headers },
      );

      if (retryResponse.data.error) {
        const retryErrorCode = retryResponse.data.error.errorCode?.toString() || 'unknown';
        logger.error(`Retry failed with error ${retryErrorCode}: ${retryResponse.data.error.errorMessage}`);
        return {
          success: false,
          errorCode: retryErrorCode,
          message: retryResponse.data.error.errorMessage || this.getErrorMessage(retryErrorCode),
        };
      }

      logger.info(`Card re-added successfully after deletion.`);
      return {
        session: retryResponse.data.result.session,
        otpSentPhone: retryResponse.data.result.otpSentPhone,
        success: true,
      };
    } catch (retryError) {
      logger.error(`Error during the retry API call: ${retryError.message}`);
      const errorData = retryError.response?.data?.error;
      const errorCode = errorData?.errorCode?.toString() || 'api_error';
      return {
        success: false,
        errorCode: errorCode,
        message: errorData?.errorMessage || "Qayta urinishda serverda xatolik yuz berdi.",
      };
    }
  }


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
        const errorCode = apiResponse.data.error.errorCode?.toString() || 'unknown';

        if (errorCode === '-108') {
          return this.deleteCardAndRetry(userId, dto.cardNumber, payload, headers);
        }

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
      logger.error(`Error in addCard: ${error?.message}`, { data: error.response?.data });

      if (error.response?.data?.error) {
        const errorData = error.response.data.error;
        const errorCode = errorData.errorCode?.toString() || 'unknown';

        if (errorCode === '-108') {
          const { uid: userId } = this.decodeAccessToken(dto.token);
          const headers = this.getHeaders();
          const payload: ExternalAddCardDto = {
            userId,
            cardNumber: dto.cardNumber,
            expireDate: dto.expireDate,
            userPhone: dto.userPhone,
          };
          return this.deleteCardAndRetry(userId, dto.cardNumber, payload, headers);
        }

        return {
          success: false,
          errorCode: errorCode,
          message:
            errorData.errorMessage ||
            this.getErrorMessage(errorCode),
        };
      }

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
        // Mark as active (remove these lines if properties don't exist)
        // existingCard.isDeleted = false;
        // existingCard.deletedAt = undefined;
        (existingCard as any).isDeleted = false;
        (existingCard as any).deletedAt = undefined;
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

      logger.info(`User card processed: ${JSON.stringify(userCard)}`);

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
}

import { Bot, Context, InlineKeyboard, SessionFlavor } from 'grammy';
import { config, SubscriptionType } from '../../../shared/config';
import {
  IUserDocument,
  UserModel,
} from '../../../shared/database/models/user.model';
import logger from '../../../shared/utils/logger';
import { CardType, UserCardsModel } from '../../../shared/database/models/user-cards.model';
import axios from 'axios';
import { uzcardAuthHash } from '../../../shared/utils/hashing/uzcard-auth-hash';

interface SessionData {
  pendingSubscription?: {
    type: SubscriptionType;
  };
}

type BotContext = Context & SessionFlavor<SessionData>;

export class SubscriptionMonitorService {
  private bot: Bot<BotContext>;
  private readonly baseUrl = process.env.UZCARD_BASE_URL;

  constructor(bot: Bot<BotContext>) {
    this.bot = bot;
  }

  private getHeaders() {
    const authHeader = uzcardAuthHash();
    return {
      'Content-Type': 'application/json; charset=utf-8',
      Accept: 'application/json',
      Authorization: authHeader,
      Language: 'uz',
    };
  }

  private async performDirectPayment(telegramId: number, planId: string): Promise<{ success: boolean; message?: string }> {
    try {
      const user = await UserModel.findOne({ telegramId });
      if (!user) {
        logger.error(`User not found for Telegram ID: ${telegramId}`);
        return { success: false, message: 'User not found' };
      }

      const card = await UserCardsModel.findOne({
        userId: user._id,
        cardType: CardType.UZCARD,
        verified: true
      });

      if (!card) {
        logger.error(`Card not found for User ID: ${user._id}`);
        return { success: false, message: 'Card not found' };
      }

      const { Plan } = require('../../../shared/database/models/plans.model');
      const plan = await Plan.findById(planId);

      if (!plan) {
        logger.error(`Plan not found for Plan ID: ${planId}`);
        return { success: false, message: 'Plan not found' };
      }

      const headers = this.getHeaders();
      const payload = {
        userId: card.userId.toString(),
        cardId: card.cardToken,
        amount: Number(plan.price) || 5555,
        extraId: `subscription-auto-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
        sendOtp: false,
      };

      const apiResponse = await axios.post(
        `${this.baseUrl}/Payment/payment`,
        payload,
        { headers },
      );

      logger.info(
        `UzCard API auto-renewal response for user ${telegramId}: ${JSON.stringify(apiResponse.data)}`,
      );

      if (apiResponse.data.error !== null) {
        const errorMessage = apiResponse.data.error?.errorMessage || 'Payment failed';
        return { success: false, message: errorMessage };
      }

      if (!apiResponse.data.result) {
        return { success: false, message: 'Payment not confirmed' };
      }

      logger.info(`Auto-renewal payment successful for user ${telegramId}`);
      return { success: true };
    } catch (error: any) {
      logger.error(`Error in performDirectPayment for user ${telegramId}:`, error);
      return {
        success: false,
        message: error.response?.data?.error?.errorMessage || 'Payment processing error'
      };
    }
  }

  async checkExpiringSubscriptions(): Promise<void> {
    const threeDaysFromNow = new Date();
    threeDaysFromNow.setDate(threeDaysFromNow.getDate() + 3);

    // Find users whose subscriptions expire in 3 days and are still active
    const expiringUsers = await UserModel.find({
      subscriptionEnd: {
        $gte: new Date(),
        $lte: threeDaysFromNow,
      },
      isActive: true,
    });

    for (const user of expiringUsers) {
      // Try automatic renewal first for subscription users
      if (user.subscriptionType === 'subscription') {
        const renewed = await this.attemptAutoRenewal(user);
        if (!renewed) {
          // Only send warning if auto-renewal failed
          await this.sendExpirationWarning(user);
        }
      } else {
        // For one-time payment users, just send warning
        await this.sendExpirationWarning(user);
      }
    }
  }

  async handleExpiredSubscriptions(): Promise<void> {
    const now = new Date();

    // Find users whose subscriptions have expired but haven't been kicked
    const expiredUsers = await UserModel.find({
      subscriptionEnd: { $lt: now },
      isActive: true,
      isKickedOut: false,
    });

    for (const user of expiredUsers) {
      await this.handleExpiredUser(user);
    }
  }

  private async sendExpirationWarning(user: IUserDocument): Promise<void> {
    try {
      const daysLeft = Math.ceil(
        (user.subscriptionEnd.getTime() - new Date().getTime()) /
        (1000 * 60 * 60 * 24),
      );

      const keyboard = new InlineKeyboard()
        .text('🔄 Obunani yangilash', 'renew')
        .row()
        .text('📊 Obuna holati', 'check_status');

      const message =
        `⚠️ Ogohlantirish!\n\n` +
        `Sizning obunangiz ${daysLeft} kundan so'ng tugaydi.\n` +
        `Agar obunani yangilamasangiz, kanal a'zoligidan chiqarilasiz.\n\n` +
        `Obunani yangilash uchun quyidagi tugmani bosing:`;

      await this.bot.api.sendMessage(user.telegramId, message, {
        reply_markup: keyboard,
      });

      logger.info(`Sent expiration warning to user ${user.telegramId}`);
    } catch (error) {
      logger.error(
        `Error sending expiration warning to user ${user.telegramId}:`,
        error,
      );
    }
  }

  private async attemptAutoRenewal(user: IUserDocument): Promise<boolean> {
    try {
      logger.info(`Attempting auto-renewal for user ${user.telegramId}`);

      // Check if user has a saved card
      const savedCard = await UserCardsModel.findOne({
        userId: user._id,
        verified: true,
        cardType: CardType.UZCARD,
      });

      if (!savedCard) {
        logger.info(`No saved card found for user ${user.telegramId}`);
        return false;
      }

      // Get user's plan
      const planId = savedCard.planId?.toString();
      if (!planId) {
        logger.warn(`No plan ID found for user ${user.telegramId}`);
        return false;
      }

      // Attempt payment directly without UzCardApiService to avoid circular dependency
      const paymentResult = await this.performDirectPayment(
        user.telegramId,
        planId,
      );

      if (paymentResult.success) {
        logger.info(`Auto-renewal successful for user ${user.telegramId}`);

        // Update user subscription
        const newEndDate = new Date();
        newEndDate.setDate(newEndDate.getDate() + 30);

        user.subscriptionEnd = newEndDate;
        user.isActive = true;
        await user.save();

        // Send success message to user
        const keyboard = new InlineKeyboard()
          .text('📊 Obuna holati', 'check_status')
          .row()
          .text('🏠 Asosiy menyu', 'main_menu');

        const message =
          `✅ Obunangiz muvaffaqiyatli yangilandi!\n\n` +
          `📆 Yangi tugash sanasi: ${newEndDate
            .getDate()
            .toString()
            .padStart(2, '0')}.${(newEndDate.getMonth() + 1)
              .toString()
              .padStart(2, '0')}.${newEndDate.getFullYear()}\n\n` +
          `To'lov saqlangan kartangizdan avtomatik amalga oshirildi.`;

        await this.bot.api.sendMessage(user.telegramId, message, {
          reply_markup: keyboard,
        });

        return true;
      } else {
        logger.warn(
          `Auto-renewal failed for user ${user.telegramId}: ${paymentResult.message}`,
        );

        // Send payment failure notification
        const keyboard = new InlineKeyboard()
          .text('🔄 Obunani yangilash', 'subscribe')
          .row()
          .text('📊 Obuna holati', 'check_status');

        const message =
          `⚠️ Obunangizni avtomatik yangilashda xatolik yuz berdi.\n\n` +
          `Sabab: ${paymentResult.message || 'Kartada yetarli mablag\' mavjud emas yoki kartada muammo bor.'}\n\n` +
          `Iltimos, obunangizni qo'lda yangilang yoki kartangizni tekshiring.`;

        await this.bot.api.sendMessage(user.telegramId, message, {
          reply_markup: keyboard,
        });

        return false;
      }
    } catch (error) {
      logger.error(`Error in auto-renewal for user ${user.telegramId}:`, error);
      return false;
    }
  }

  private async handleExpiredUser(user: IUserDocument): Promise<void> {
    try {
      if (user.activeInviteLink) {
        try {
          await this.bot.api.revokeChatInviteLink(
            config.CHANNEL_ID,
            user.activeInviteLink,
          );
          logger.info('Revoked invite link for expired user', {
            telegramId: user.telegramId,
          });
        } catch (error) {
          logger.warn('Failed to revoke invite link for expired user', {
            telegramId: user.telegramId,
            error,
          });
        }

        user.activeInviteLink = undefined;
      }

      // Ban foydalanuvchini kanalga qayta kirishdan to'liq to'sish uchun
      await this.bot.api.banChatMember(config.CHANNEL_ID, user.telegramId);

      // Update user status
      user.isActive = false;
      user.isKickedOut = true;
      await user.save();

      const keyboard = new InlineKeyboard()
        .text("🎯 Qayta obuna bo'lish", 'subscribe')
        .row()
        .text('📊 Obuna holati', 'check_status');

      const message =
        `❌ Sizning obunangiz muddati tugadi va siz kanaldan chiqarildingiz.\n\n` +
        `Qayta obuna bo'lish uchun quyidagi tugmani bosing:`;

      await this.bot.api.sendMessage(user.telegramId, message, {
        reply_markup: keyboard,
      });

      logger.info(`Handled expired subscription for user ${user.telegramId}`);
    } catch (error) {
      logger.error(`Error handling expired user ${user.telegramId}:`, error);
    }
  }
}

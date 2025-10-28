import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import {
  Bot,
  Context,
  InlineKeyboard,
  InputFile,
  session,
  SessionFlavor,
} from 'grammy';
import { config, SubscriptionType } from '../../shared/config';
import { SubscriptionService } from './services/subscription.service';
import { SubscriptionMonitorService } from './services/subscription-monitor.service';
import { SubscriptionChecker } from './services/subscription-checker';
import logger from '../../shared/utils/logger';
import { IPlanDocument, Plan } from '../../shared/database/models/plans.model';
import { IUserDocument, UserModel } from '../../shared/database/models/user.model';
import { generatePaymeLink } from '../../shared/generators/payme-link.generator';
import {
  ClickRedirectParams,
  getClickRedirectLink,
} from '../../shared/generators/click-redirect-link.generator';
import { buildSubscriptionCancellationLink, buildSubscriptionManagementLink } from '../../shared/utils/payment-link.util';
import mongoose from 'mongoose';
import { CardType, UserCardsModel } from '../../shared/database/models/user-cards.model';
import { FlowStepType, SubscriptionFlowTracker } from 'src/shared/database/models/subscription.follow.tracker';
import {
  Transaction,
  TransactionStatus,
} from '../../shared/database/models/transactions.model';
import { join } from 'node:path';

interface SessionData {
  pendingSubscription?: {
    type: SubscriptionType;
  };
  hasAgreedToTerms?: boolean;
  selectedService: string;
  mainMenuMessageId?: number;
  pendingOnetimePlanId?: string;
  introStep?: number;
  introActive?: boolean;
}

type BotContext = Context & SessionFlavor<SessionData>;

type IntroSlide =
  | {
      type: 'video';
      filePath: string;
      caption: (ctx: BotContext) => string;
    }
  | {
      type: 'message';
      text: (ctx: BotContext) => string;
    };

@Injectable()
export class BotService implements OnModuleInit, OnModuleDestroy {
  private bot: Bot<BotContext>;
  private subscriptionService: SubscriptionService;
  private subscriptionMonitorService: SubscriptionMonitorService;
  private subscriptionChecker: SubscriptionChecker;
  private readonly ADMIN_IDS = [1487957834, 7554617589, 85939027, 2022496528];
  private readonly subscriptionTermsLink: string;
  private readonly introSlides: IntroSlide[] = [
    {
      type: 'video',
      filePath: join(process.cwd(), 'mun.mp4'),
      caption: (ctx) => {
        const name = ctx.from?.first_name ?? "do'st";
        return `Assalomu alaykum, ${name}! 👋`;
      },
    },
  ];


  constructor() {
    this.bot = new Bot<BotContext>(config.BOT_TOKEN);
    this.subscriptionService = new SubscriptionService(this.bot);
    this.subscriptionMonitorService = new SubscriptionMonitorService(this.bot);
    this.subscriptionChecker = new SubscriptionChecker(
      this.subscriptionMonitorService,
    );
    this.subscriptionTermsLink = this.resolveSubscriptionTermsLink();
    this.setupMiddleware();
    this.setupHandlers();
  }

  private buildCancellationNotice(telegramId?: number): string {
    const link = telegramId
      ? buildSubscriptionCancellationLink(telegramId)
      : undefined;

    if (link) {
      return `Obunani bekor qilish uchun <a href="${link}">bu havola</a> orqali ariza yuboring.`;
    }

    return 'Obunani bekor qilish uchun botdagi "Obuna holati" bo‘limi orqali qo‘llab-quvvatlashga murojaat qiling.';
  }

  private resolveSubscriptionTermsLink(): string {
    const configured = config.SUBSCRIPTION_TERMS_URL?.trim();
    if (configured) {
      return configured;
    }

    const derived = buildSubscriptionManagementLink('subscription/terms');
    if (derived) {
      return derived;
    }

    return 'https://telegra.ph/Yulduzlar-Bashorati-Premium--OMMAVIY-OFERTA-06-26';
  }

  async onModuleInit(): Promise<void> {
    // Start the bot asynchronously to avoid blocking application startup
    this.startAsync();
  }

  async onModuleDestroy(): Promise<void> {
    await this.stop();
  }

  public async start(): Promise<void> {
    this.subscriptionChecker.start();

    await this.bot.start({
      allowed_updates: [
        'message',
        'callback_query',
        'chat_join_request',
        'chat_member',
        'my_chat_member',
      ],
      onStart: () => {
        logger.info('Bot started');
      },
    });
  }

  public async stop(): Promise<void> {
    logger.info('Stopping bot...');
    await this.bot.stop();
  }

  async handleCardAddedWithoutBonus(userId: string, telegramId: number, cardType: CardType, plan: IPlanDocument, username?: string, selectedService?: string) {
    try {
      const user = await UserModel.findById(userId);
      if (!user) {
        return;
      }

      if (!plan) {
        return;
      }

      user.subscriptionType = 'subscription'
      user.save();

      // Create regular subscription without bonus
      const {
        user: subscription,
        wasKickedOut,
        success
      } = await this.subscriptionService.renewSubscriptionWithCard(
        userId,
        telegramId,
        cardType,
        plan,
        username,
        selectedService
      );

      if (success) {
        await this.revokeUserInviteLink(subscription, false);

        const privateLink = await this.getPrivateLink();
        subscription.activeInviteLink = privateLink.invite_link;
        await subscription.save();

        const keyboard = new InlineKeyboard()
          .url("🔗 Kanalga kirish", privateLink.invite_link)
          .row()
          .text("📊 Obuna holati", "check_status")
          .row()
          .text("🔙 Asosiy menyu", "main_menu");

        // Format the end date
        const endDate = new Date(subscription.subscriptionEnd);
        const endDateFormatted = `${endDate.getDate().toString().padStart(2, '0')}.${(endDate.getMonth() + 1).toString().padStart(2, '0')}.${endDate.getFullYear()}`;

        let messageText = `✅ To'lov muvaffaqiyatli amalga oshirildi va kartangiz saqlandi!\n\n` +
          `📆 Yangi obuna muddati: ${endDateFormatted} gacha\n\n` +
          `Quyidagi havola orqali kanalga kirishingiz mumkin:`;

        await this.bot.api.sendMessage(
          telegramId,
          messageText,
          {
            reply_markup: keyboard,
            parse_mode: "HTML"
          }
        );

      }

    } catch (error) {
      await this.bot.api.sendMessage(
        telegramId,
        "⚠️ Kartangiz qo'shildi, lekin obunani yangilashda xatolik yuz berdi. Iltimos, administrator bilan bog'laning. @sssupporttbot"
      );
    }


  }
  async handleAutoSubscriptionSuccess(userId: string, telegramId: number, planId: string, username?: string): Promise<void> {
    try {
      const plan = await Plan.findById(planId);

      if (!plan) {
        logger.error(`Plan with name 'Wrestling' not found in handleAutoSubscriptionSuccessForWrestling`);
        return;
      }

      await SubscriptionFlowTracker.create({
        telegramId,
        username,
        userId,
        step: FlowStepType.COMPLETED_SUBSCRIPTION,
      });

      const user = await UserModel.findById(userId);

      if (!user) {
        throw new Error('User not found');
      }


      const { user: subscription } = await this.subscriptionService.createSubscriptionWithCard(
        userId,
        plan,
        username,
        30
      );

      await this.revokeUserInviteLink(subscription, false);

      const privateLink = await this.getPrivateLink();
      subscription.activeInviteLink = privateLink.invite_link;
      await subscription.save();

      const keyboard = new InlineKeyboard()
        .url("🔗 Kanalga kirish", privateLink.invite_link)
        .row()
        .text("🔙 Asosiy menyu", "main_menu");

      // Format end date in DD.MM.YYYY format
      const endDateFormatted = `${subscription.subscriptionEnd.getDate().toString().padStart(2, '0')}.${(subscription.subscriptionEnd.getMonth() + 1).toString().padStart(2, '0')}.${subscription.subscriptionEnd.getFullYear()}`;


      let messageText = `🎉 Tabriklaymiz! Munajjim premium obunasi muvaffaqiyatli faollashtirildi!\n\n`;

      messageText += `📆 Obuna muddati: ${endDateFormatted} gacha\n\n`;


      // if (wasKickedOut) {
      //     //TODO we aren't banning users so this is not necessary, but I am keeping them for now
      //     await this.bot.api.unbanChatMember(config.CHANNEL_ID, telegramId);
      //     messageText += `ℹ️ Sizning avvalgi bloklanishingiz bekor qilindi. ` +
      //         `Quyidagi havola orqali kanalga qayta kirishingiz mumkin:`;
      // } else {
      //     messageText += `Quyidagi havola orqali kanalga kirishingiz mumkin:`;
      // }

      messageText += `Quyidagi havola orqali kanalga kirishingiz mumkin:`;


      await this.bot.api.sendMessage(
        telegramId,
        messageText,
        {
          reply_markup: keyboard,
          parse_mode: "HTML"
        }
      );

    } catch (error) {

      // Send error message to user
      await this.bot.api.sendMessage(
        telegramId,
        "⚠️ Avtomatik to'lov faollashtirildi, lekin obunani faollashtirish bilan bog'liq muammo yuzaga keldi. Iltimos, administrator bilan bog'laning."
      );
    }

  }
  async handlePaymentSuccess(
    userId: string,
    telegramId: number,
    username?: string,
  ): Promise<void> {
    console.log('WATCH! @@@ handlePaymentSuccess is being called! ');

    try {
      const plan = await Plan.findOne({ name: 'Basic' });

      if (!plan) {
        logger.error('No plan found with name "Basic"');
        return;
      }

      const { user: subscription, wasKickedOut } =
        await this.subscriptionService.createSubscription(
          userId,
          plan,
          username,
        );

      await this.revokeUserInviteLink(subscription, false);

      subscription.subscriptionType = 'onetime';

      const privateLink = await this.getPrivateLink();
      subscription.activeInviteLink = privateLink.invite_link;
      await subscription.save();

      const keyboard = new InlineKeyboard()
        .url('🔗 Kanalga kirish', privateLink.invite_link)
        .row()
        .text('🔙 Asosiy menyu', 'main_menu');

      let messageText =
        `🎉 Tabriklaymiz! To'lov muvaffaqiyatli amalga oshirildi!\n\n` +
        `⏰ Obuna tugash muddati: ${subscription.subscriptionEnd.getDate().toString().padStart(2, '0')}.${(subscription.subscriptionEnd.getMonth() + 1).toString().padStart(2, '0')}.${subscription.subscriptionEnd.getFullYear()}\n\n`;

      if (wasKickedOut) {
        await this.bot.api.unbanChatMember(config.CHANNEL_ID, telegramId);
        messageText +=
          `ℹ️ Sizning avvalgi bloklanishingiz bekor qilindi. ` +
          `Quyidagi havola orqali kanalga qayta kirishingiz mumkin:`;
      } else {
        messageText += `Quyidagi havola orqali kanalga kirishingiz mumkin:`;
      }

      await this.bot.api.sendMessage(telegramId, messageText, {
        reply_markup: keyboard,
        parse_mode: 'HTML',
      });
      console.log('WATCH! @@@ handlePaymentSuccess sent the message');
    } catch (error) {
      logger.error('Payment success handling error:', error);
      await this.bot.api.sendMessage(
        telegramId,
        "⚠️ To'lov amalga oshirildi, lekin obunani faollashtirish bilan bog'liq muammo yuzaga keldi. Iltimos, administrator bilan bog'laning.",
      );
    }
  }

  async handleSubscriptionSuccess(
    userId: string,
    planId: string,
    bonusDays: number,
    selectedService: string,
  ): Promise<void> {
    let telegramId: number | undefined;

    logger.warn(
      `Selected service in handleSubscriptionSuccess ${selectedService}`,
    );
    try {
      const plan = await Plan.findById(planId);
      if (!plan) {
        logger.error('No plan found with name "Basic"');
        return;
      }

      const user = await UserModel.findById(userId);
      if (!user) {
        logger.error(`User not found with ID: ${userId}`);
        return;
      }

      telegramId = user.telegramId;
      if (!telegramId) {
        logger.error(`Telegram ID not found for user: ${userId}`);
        return;
      }

      const { user: subscription, wasKickedOut } =
        await this.subscriptionService.createBonusSubscription(
          userId,
          plan,
          bonusDays,
          user.username,
          'yulduz',
        );

      await this.revokeUserInviteLink(subscription, false);

      const privateLink = await this.getPrivateLink();
      subscription.activeInviteLink = privateLink.invite_link;
      await subscription.save();

      const keyboard = new InlineKeyboard()
        .url('🔗 Kanalga kirish', privateLink.invite_link)
        .row()
        .text('🔙 Asosiy menyu', 'main_menu');

      const bonusEndFormatted = `${subscription.subscriptionEnd.getDate().toString().padStart(2, '0')}.${(subscription.subscriptionEnd.getMonth() + 1).toString().padStart(2, '0')}.${subscription.subscriptionEnd.getFullYear()}`;

      let messageText =
        `🎉 Tabriklaymiz! UzCard orqali ${plan.name} uchun obuna muvaffaqiyatli faollashtirildi!\n\n` +
        `🎁 ${bonusDays} kunlik bonus: ${bonusEndFormatted} gacha\n\n`;

      if (wasKickedOut) {
        await this.bot.api.unbanChatMember(config.CHANNEL_ID, telegramId);
        messageText += `ℹ️ Sizning avvalgi bloklanishingiz bekor qilindi. `;
      }

      messageText += `Quyidagi havola orqali kanalga kirishingiz mumkin:`;

      await this.bot.api.sendMessage(telegramId, messageText, {
        reply_markup: keyboard,
        parse_mode: 'HTML',
      });

      logger.info(
        `UzCard subscription success handled for user ${userId} with ${bonusDays} bonus days`,
      );
    } catch (error) {
      logger.error(`Error in handleUzCardSubscriptionSuccess: ${error}`);
      if (telegramId) {
        await this.bot.api.sendMessage(
          telegramId,
          "⚠️ UzCard orqali obunani faollashtirishda xatolik. Iltimos, administrator bilan bog'laning.",
        );
      }
    }
  }

  async handlePaymentSuccessForUzcard(
    userId: string,
    telegramId: number,
    username?: string,
    // fiscalQr?: string | undefined,
    selectedService?: string,
  ): Promise<void> {
    logger.info(`Selected service on handlePaymentSuccess: ${selectedService}`);
    try {
      const plan = await Plan.findOne({ selectedName: selectedService });

      if (!plan) {
        return;
      }

      const subscription = await this.subscriptionService.createSubscription(
        userId,
        plan,
        username,
      );

      let messageText: string = '';

      await this.revokeUserInviteLink(subscription.user, false);

      const privateLink = await this.getPrivateLink();
      subscription.user.activeInviteLink = privateLink.invite_link;
      await subscription.user.save();
      const keyboard = new InlineKeyboard()
        .url('🔗 Kanalga kirish', privateLink.invite_link)
        .row()
        .text('🔙 Asosiy menyu', 'main_menu');

      // if (fiscalQr) {
      //   keyboard.row().url("🧾 Chekni ko'rish", fiscalQr);
      // }

      const subscriptionEndDate = subscription.user.subscriptionEnd;

      messageText =
        `🎉 Tabriklaymiz! Munajjim premium uchun to'lov muvaffaqiyatli amalga oshirildi!\n\n` +
        `⏰ Obuna tugash muddati: ${subscriptionEndDate.getDate().toString().padStart(2, '0')}.${(subscriptionEndDate.getMonth() + 1).toString().padStart(2, '0')}.${subscriptionEndDate.getFullYear()}\n\n`;

      messageText += `Quyidagi havola orqali kanalga kirishingiz mumkin:`;

      // if (fiscalQr) {
      //   messageText += `\n\n📋 To'lov cheki QR kodi mavjud. Chekni ko'rish uchun quyidagi tugmani bosing.`;
      // }

      await UserModel.updateOne(
        { telegramId: telegramId },
        { $set: { subscribedTo: selectedService } },
      );

      const user1 = await UserModel.findOne({
        telegramId: telegramId,
      });

      // @ts-ignore
      logger.info(`User updated with subscribedTo: ${user1.subscribedTo}`);

      await this.bot.api.sendMessage(telegramId, messageText, {
        reply_markup: keyboard,
        parse_mode: 'HTML',
      });
    } catch (error) {
      logger.error(`Error in handlePaymentSuccessForUzcard: ${error}`);
      await this.bot.api.sendMessage(
        telegramId,
        "⚠️ To'lov amalga oshirildi, lekin obunani faollashtirish bilan bog'liq muammo yuzaga keldi. Iltimos, administrator bilan bog'laning. @sssupporttbot",
      );
    }
  }


  private async startAsync(): Promise<void> {
    try {
      await this.start();
    } catch (error) {
      logger.error('Failed to start bot:', error);
    }
  }

  // ... rest of your methods remain the same ...
  private setupMiddleware(): void {
    this.bot.use(
      session({
        initial(): SessionData {
          return {
            selectedService: 'yulduz',
            hasAgreedToTerms: false, // Initialize as false by default
            introActive: false,
          };
        },
      }),
    );
    this.bot.use((ctx, next) => {
      logger.info(`user chatId: ${ctx.from?.id}`);
      return next();
    });

    this.bot.catch((err) => {
      logger.error('Bot error:', err);
    });
  }

  private setupHandlers(): void {
    this.bot.command('start', this.handleStart.bind(this));
    this.bot.command('admin', this.handleAdminCommand.bind(this));
    this.bot.on('callback_query', this.handleCallbackQuery.bind(this));
    this.bot.on('chat_join_request', this.handleChatJoinRequest.bind(this));
  }

  private async handleCallbackQuery(ctx: BotContext): Promise<void> {
    if (!ctx.callbackQuery?.data) return;

    const data = ctx.callbackQuery.data;
    if (!data) return;

    if (data.startsWith('onetime|')) {
      const [, provider] = data.split('|');
      if (
        provider === 'uzcard' ||
        provider === 'payme' ||
        provider === 'click'
      ) {
        await this.handleOneTimePaymentProviderSelection(
          ctx,
          provider as 'uzcard' | 'payme' | 'click',
        );
      } else {
        await ctx.answerCallbackQuery(
          "Noma'lum to'lov turi tanlandi.",
          { show_alert: true },
        );
      }
      return;
    }

    if (data === 'main_menu') {
      ctx.session.hasAgreedToTerms = false;
    }

    const handlers: { [key: string]: (ctx: BotContext) => Promise<void> } = {
      intro_done: this.handleIntroDone.bind(this),
      payment_type_onetime: this.handleOneTimePayment.bind(this),
      payment_type_subscription: this.handleSubscriptionPayment.bind(this),
      back_to_payment_types: this.showPaymentTypeSelection.bind(this),
      subscribe: this.handleSubscribeCallback.bind(this),
      check_status: this.handleStatus.bind(this),
      cancel_subscription: this.handleSubscriptionCancellation.bind(this),
      payme_subscription_unavailable: this.handlePaymeSubscriptionUnavailable.bind(this),
      main_menu: this.showMainMenu.bind(this),
      confirm_subscribe_basic: this.confirmSubscription.bind(this),
      agree_terms: this.handleAgreement.bind(this),

      not_supported_international: async (ctx) => {
        await ctx.answerCallbackQuery({
          text: "⚠️ Kechirasiz, hozircha bu to'lov turi mavjud emas.",
          show_alert: true,
        } as any);
      },
    };

    const handler = handlers[data];
    if (handler) {
      await handler(ctx);
    }
  }

  private async showMainMenu(ctx: BotContext): Promise<void> {
    ctx.session.hasAgreedToTerms = false;

    const keyboard = new InlineKeyboard().text("🎯 Obuna bo'lish", 'subscribe');

    const message =
      `Assalomu alaykum, ${ctx.from?.first_name}! 👋\n\n` +
      'Munajjim Premium galaktikasiga xush kelibsiz! 🏆\n\n' +
      '🎁 30 kunlik bepul astro-bashoratlar va maxsus tavsiyalarni olish uchun ' +
      'pastdagi <b>“Obuna bo‘lish”</b> tugmasini bosing.';

    const chatId = ctx.chat?.id;

    if (!ctx.callbackQuery && chatId && ctx.session.mainMenuMessageId) {
      try {
        await ctx.api.deleteMessage(chatId, ctx.session.mainMenuMessageId);
      } catch (error) {
        logger.warn('Old menu message could not be deleted', {
          chatId,
          messageId: ctx.session.mainMenuMessageId,
          error,
        });
      }
    }

    if (ctx.callbackQuery) {
      try {
        await ctx.editMessageText(message, {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        });
        const messageId = ctx.callbackQuery.message?.message_id;
        if (messageId) {
          ctx.session.mainMenuMessageId = messageId;
        }
      } catch (error) {
        logger.warn('Failed to edit main menu message, sending new message', {
          error,
        });
        if (chatId) {
          const sentMessage = await ctx.reply(message, {
            reply_markup: keyboard,
            parse_mode: 'HTML',
          });
          ctx.session.mainMenuMessageId = sentMessage.message_id;
        }
      }
      return;
    }

    const sentMessage = await ctx.reply(message, {
      reply_markup: keyboard,
      parse_mode: 'HTML',
    });
    ctx.session.mainMenuMessageId = sentMessage.message_id;
  }

  private async handleStart(ctx: BotContext): Promise<void> {
    ctx.session.hasAgreedToTerms = false;

    const chatId = ctx.chat?.id;
    const messageId = ctx.message?.message_id;

    if (chatId && messageId) {
      try {
        await ctx.api.deleteMessage(chatId, messageId);
      } catch (error) {
        logger.warn('Start command message could not be deleted', {
          chatId,
          messageId,
          error,
        });
      }

      await this.clearChatHistory(ctx, messageId);
    } else {
      await this.clearChatHistory(ctx);
    }

    ctx.session.mainMenuMessageId = undefined;

    await this.createUserIfNotExist(ctx);
    await this.startIntroduction(ctx);
  }

  private async startIntroduction(ctx: BotContext): Promise<void> {
    ctx.session.introStep = 0;
    ctx.session.introActive = true;
    await this.showIntroSlide(ctx);
  }

  private async showIntroSlide(ctx: BotContext): Promise<void> {
    const step = ctx.session.introStep ?? 0;
    const slide = this.introSlides[step];

    if (!slide) {
      ctx.session.introActive = false;
      ctx.session.introStep = undefined;
      await this.showMainMenu(ctx);
      return;
    }

    const keyboard = this.buildIntroKeyboard(step);

    try {
      if (slide.type === 'video') {
        await ctx.replyWithVideo(new InputFile(slide.filePath), {
          caption: slide.caption(ctx),
          parse_mode: 'HTML',
          reply_markup: keyboard,
        });
        await this.sendIntroSticker(ctx);
      } else {
        await ctx.reply(slide.text(ctx), {
          parse_mode: 'HTML',
          reply_markup: keyboard,
        });
      }
    } catch (error) {
      logger.error('Failed to deliver intro slide', {
        step,
        error,
      });

      await ctx.reply(
        "⚠️ Video yuborishda xatolik yuz berdi. Iltimos, /start buyrug'ini qayta yuboring.",
      );
      ctx.session.introActive = false;
      ctx.session.introStep = undefined;
      await this.showMainMenu(ctx);
    }
  }

  private buildIntroKeyboard(_: number): InlineKeyboard {
    return new InlineKeyboard().text("🚀 Menyuga o'tish", 'intro_done');
  }

  private async sendIntroSticker(ctx: BotContext): Promise<void> {
    const stickerId = config.INTRO_STICKER_ID?.trim();

    if (!stickerId) {
      await ctx.reply("🤗 Obuna bo'lasiz-a? Pastdagi tugma orqali menyuga o'ting.");
      return;
    }

    try {
      await ctx.replyWithSticker(stickerId);
    } catch (error) {
      logger.warn('Failed to send intro sticker, falling back to text', {
        error,
      });
      await ctx.reply("🤗 Obuna bo'lasiz-a? Pastdagi tugma orqali menyuga o'ting.");
    }
  }

  private async handleIntroDone(ctx: BotContext): Promise<void> {
    await this.answerAndDisableIntro(ctx);

    ctx.session.introActive = false;
    ctx.session.introStep = undefined;
    ctx.session.hasAgreedToTerms = false;
    await this.showTermsMessage(ctx, { preferEdit: false });
  }

  private async answerAndDisableIntro(ctx: BotContext): Promise<void> {
    try {
      await ctx.answerCallbackQuery();
    } catch (error) {
      logger.warn('Failed to acknowledge intro callback', { error });
    }

    try {
      await ctx.editMessageReplyMarkup();
    } catch (error) {
      logger.warn('Failed to clear intro keyboard', { error });
    }
  }

  private async handleStatus(ctx: BotContext): Promise<void> {
    try {
      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId });

      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      if (!user.subscriptionStart && !user.subscriptionEnd) {
        const keyboard = new InlineKeyboard()
          .text("🎯 Obuna bo'lish", 'subscribe')
          .row()
          .text('🔙 Asosiy menyu', 'main_menu');

        await ctx.editMessageText(
          "Siz hali obuna bo'lmagansiz 🤷‍♂️\nObuna bo'lish uchun quyidagi tugmani bosing:",
          { reply_markup: keyboard },
        );
        return;
      }

      const subscription = await this.subscriptionService.getSubscription(
        user._id as string,
      );

      if (!subscription) {
        const keyboard = new InlineKeyboard()
          .text("🎯 Obuna bo'lish", 'subscribe')
          .row()
          .text('🔙 Asosiy menyu', 'main_menu');

        await ctx.editMessageText(
          "Hech qanday obuna topilmadi 🤷‍♂️\nObuna bo'lish uchun quyidagi tugmani bosing:",
          { reply_markup: keyboard },
        );
        return;
      }

      const status = subscription.isActive ? '✅ Faol' : '❌ Muddati tugagan';
      const expirationLabel = subscription.isActive
        ? '⏰ Obuna tugash muddati:'
        : '⏰ Obuna tamomlangan sana:';

      let subscriptionStartDate = 'Mavjud emas';
      let subscriptionEndDate = 'Mavjud emas';

      if (subscription.subscriptionStart) {
        const d = subscription.subscriptionStart;
        subscriptionStartDate = `${d.getDate().toString().padStart(2, '0')}.${(d.getMonth() + 1).toString().padStart(2, '0')}.${d.getFullYear()}`;
      }
      if (subscription.subscriptionEnd) {
        const d = subscription.subscriptionEnd;
        subscriptionEndDate = `${d.getDate().toString().padStart(2, '0')}.${(d.getMonth() + 1).toString().padStart(2, '0')}.${d.getFullYear()}`;
      }

      const message = `🎫 <b>Obuna ma'lumotlari:</b>\n
📅 Holati: ${status}
📆 Obuna bo'lgan sana: ${subscriptionStartDate}
${expirationLabel} ${subscriptionEndDate}`;

      const keyboard = new InlineKeyboard();

      if (subscription.isActive) {
        await this.revokeUserInviteLink(subscription, false);

        const privateLink = await this.getPrivateLink();
        subscription.activeInviteLink = privateLink.invite_link;
        await subscription.save();

        keyboard.row();
        keyboard.url('🔗 Kanalga kirish', privateLink.invite_link);
      } else {
        keyboard.text("🎯 Qayta obuna bo'lish", 'subscribe');
      }

      keyboard.row().text('🔙 Asosiy menyu', 'main_menu');

      await ctx.editMessageText(message, {
        reply_markup: keyboard,
        parse_mode: 'HTML',
      });
    } catch (error) {
      logger.error('Status check error:', error);
      await ctx.answerCallbackQuery(
        'Obuna holatini tekshirishda xatolik yuz berdi.',
      );
    }
  }

  private async handleSubscribeCallback(ctx: BotContext): Promise<void> {
    try {
      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId });
      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      ctx.session.hasAgreedToTerms = false;

      await this.showTermsMessage(ctx, { preferEdit: true });
    } catch (error) {
      logger.error('Subscription plan display error:', error);
      await ctx.answerCallbackQuery(
        "Obuna turlarini ko'rsatishda xatolik yuz berdi.",
      );
    }
  }

  private async handleAgreement(ctx: BotContext): Promise<void> {
    try {
      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId });
      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      ctx.session.hasAgreedToTerms = true;

      const selectedService = ctx.session.selectedService ?? 'yulduz';
      let subscriptionUrl: string | undefined;

      try {
        const plan = await Plan.findOne({ selectedName: selectedService }).exec();
        const baseUrl =
          process.env.UZCARD_ADD_CARD_URL ??
          'http://213.230.110.176:8989/api/uzcard-api/add-card';

        if (plan) {
          const params = new URLSearchParams({
            userId: user._id.toString(),
            planId: plan._id.toString(),
            selectedService,
          });
          subscriptionUrl = `${baseUrl}?${params.toString()}`;
        } else {
          logger.warn('Plan not found for selected service, falling back to payment selection', {
            selectedService,
          });
        }
      } catch (error) {
        logger.warn('Failed to build Uzcard/Humo subscription URL', {
          telegramId,
          selectedService,
          error,
        });
      }

      if (subscriptionUrl) {
        try {
          await ctx.answerCallbackQuery();
        } catch (error) {
          logger.warn('Failed to answer agreement callback', { error });
        }

        const keyboard = new InlineKeyboard()
          .url('🎁 Uzcard/Humo (30 kun bepul)', subscriptionUrl)
          .row()
          .text('🔙 Asosiy menyu', 'main_menu');

        const message =
          '🎁 <b>Uzcard/Humo bilan 30 kunlik bepul obuna!</b>\n\n' +
          'Karta qo‘shish uchun quyidagi tugmani bosing. ⚡️' +
          ' Jarayon tugagach botga qaytib, kanalga kirish havolasini olasiz.';

        try {
          await ctx.editMessageText(message, {
            reply_markup: keyboard,
            parse_mode: 'HTML',
          });
        } catch (error) {
          logger.warn('Failed to edit agreement message, sending new one', {
            error,
          });
          await ctx.reply(message, {
            reply_markup: keyboard,
            parse_mode: 'HTML',
          });
        }
        return;
      }

      await this.showPaymentTypeSelection(ctx);
    } catch (error) {
      await ctx.answerCallbackQuery(
        "To'lov turlarini ko'rsatishda xatolik yuz berdi.",
      );
    }
  }

  private buildTermsMessage(ctx: BotContext) {
    const keyboard = new InlineKeyboard()
      .url('📄 Foydalanish shartlari', this.subscriptionTermsLink)
      .row()
      .text('✅ Qabul qilaman', 'agree_terms');

    const message =
      '📜 <b>Foydalanish shartlari va shartlar:</b>\n\n' +
      "Iltimos, obuna bo'lishdan oldin foydalanish shartlari bilan tanishib chiqing.\n\n" +
      `${this.buildCancellationNotice(ctx.from?.id)}\n\n` +
      'Tugmani bosib foydalanish shartlarini o\'qishingiz mumkin. Shartlarni qabul qilganingizdan so\'ng "Qabul qilaman" tugmasini bosing.';

    return { message, keyboard };
  }

  private async showTermsMessage(
    ctx: BotContext,
    options: { preferEdit?: boolean } = {},
  ): Promise<void> {
    const { message, keyboard } = this.buildTermsMessage(ctx);

    if (options.preferEdit && ctx.callbackQuery) {
      try {
        await ctx.editMessageText(message, {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        });
        return;
      } catch (error) {
        logger.warn('Failed to edit terms message, falling back to new message', {
          error,
        });
      }
    }

    const sent = await ctx.reply(message, {
      reply_markup: keyboard,
      parse_mode: 'HTML',
    });
    ctx.session.mainMenuMessageId = sent.message_id;
  }

  private async confirmSubscription(ctx: BotContext): Promise<void> {
    try {
      if (!ctx.session.hasAgreedToTerms) {
        await this.handleSubscribeCallback(ctx);
        return;
      }

      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId: telegramId });
      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      const plan = await Plan.findOne({
        name: 'Basic',
      });

      if (!plan) {
        logger.error('No plan found with name "Basic"');
        return;
      }

      try {
        const { user: subscription } =
          await this.subscriptionService.createSubscription(
            user._id as string,
            plan,
            ctx.from?.username,
          );

        await this.revokeUserInviteLink(subscription, false);

        const privateLink = await this.getPrivateLink();
        subscription.activeInviteLink = privateLink.invite_link;
        await subscription.save();
        const keyboard = new InlineKeyboard()
          .url('🔗 Kanalga kirish', privateLink.invite_link)
          .row()
          .text('🔙 Asosiy menyu', 'main_menu');

        const messageText =
          `🎉 Tabriklaymiz! Siz muvaffaqiyatli obuna bo'ldingiz!\n\n` +
          `⏰ Obuna tugash muddati: ${subscription.subscriptionEnd.getDate().toString().padStart(2, '0')}.${(subscription.subscriptionEnd.getMonth() + 1).toString().padStart(2, '0')}.${subscription.subscriptionEnd.getFullYear()}\n\n` +
          `Quyidagi havola orqali kanalga kirishingiz mumkin:\n\n`;

        await ctx.editMessageText(messageText, {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        });
      } catch (error) {
        if (
          error instanceof Error &&
          error.message === 'User already has an active subscription'
        ) {
          const keyboard = new InlineKeyboard()
            .text('📊 Obuna holati', 'check_status')
            .row()
            .text('🔙 Asosiy menyu', 'main_menu');

          await ctx.editMessageText(
            '⚠️ Siz allaqachon faol obunaga egasiz. Obuna holatini tekshirish uchun quyidagi tugmani bosing:',
            { reply_markup: keyboard },
          );
          return;
        }
        logger.error('Subscription confirmation error:', error);
        await ctx.answerCallbackQuery(
          'Obunani tasdiqlashda xatolik yuz berdi.',
        );
      }
    } catch (error) {
      logger.error('Subscription confirmation error:', error);
      await ctx.answerCallbackQuery('Obunani tasdiqlashda xatolik yuz berdi.');
    }
  }

  private async getPrivateLink() {
    try {
      logger.info(
        'Generating private channel invite link with channelId: ',
        config.CHANNEL_ID,
      );
      const expireAt = Math.floor(Date.now() / 1000) + 10 * 60; // 10 daqiqa amal qiladi
      const link = await this.bot.api.createChatInviteLink(
        config.CHANNEL_ID,
        {
          expire_date: expireAt,
          creates_join_request: true,
        },
      );
      if (!link) {
        throw new Error('Invite link generation returned empty result');
      }
      logger.info('Private channel invite link:', link.invite_link);
      return link;
    } catch (error) {
      logger.error('Error generating channel invite link:', error);
      throw error;
    }
  }

  private async handlePaymeSubscriptionUnavailable(
    ctx: BotContext,
  ): Promise<void> {
    await ctx.answerCallbackQuery({
      text: '⚠️ Tez orada bu Payme bilan obuna ishlaydi. Jarayonda.',
      show_alert: true,
    } as any);
  }

  private async handleSubscriptionCancellation(ctx: BotContext): Promise<void> {
    try {
      const telegramId = ctx.from?.id;
      if (!telegramId) {
        await ctx.answerCallbackQuery({
          text: "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
          show_alert: true,
        } as any);
        return;
      }

      const user = await UserModel.findOne({ telegramId }).exec();
      if (!user) {
        await ctx.answerCallbackQuery({
          text: 'Kechirasiz, siz tizimda ro‘yxatdan o‘tmagansiz.',
          show_alert: true,
        } as any);
        return;
      }

      const activeSubscription = await this.subscriptionService.getSubscription(
        user._id as string,
      );

      if (!activeSubscription || !this.userHasActiveSubscription(activeSubscription)) {
        await ctx.answerCallbackQuery({
          text: 'Kechirasiz, hozirda sizda faol obuna yo‘q.',
          show_alert: true,
        } as any);
        return;
      }

      const link = buildSubscriptionCancellationLink(telegramId);
      if (!link) {
        await ctx.answerCallbackQuery({
          text: 'Bekor qilish havolasini yaratib bo‘lmadi. Keyinroq urinib ko‘ring.',
          show_alert: true,
        } as any);
        return;
      }

      const keyboard = new InlineKeyboard()
        .url('🛑 Obunani bekor qilish', link)
        .row()
        .text('🔙 Asosiy menyu', 'main_menu');

      await ctx.editMessageText(
        'Obunani bekor qilish uchun quyidagi havoladan foydalaning. Havola shaxsiy va faqat siz uchun amal qiladi.',
        {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        },
      );
    } catch (error) {
      logger.error('Subscription cancellation link error:', error);
      await ctx.answerCallbackQuery({
        text: 'Bekor qilish havolasini olishda xatolik yuz berdi.',
        show_alert: true,
      } as any);
    }
  }

  private async handleSubscriptionPaymentWithSavedCard(
    ctx: BotContext,
    _provider: CardType,
  ): Promise<void> {
    await ctx.answerCallbackQuery({
      text: 'Saqlangan karta orqali to\'lov hozircha qo\'llab-quvvatlanmaydi.',
      show_alert: true,
    } as any);
  }

  private async createUserIfNotExist(ctx: BotContext): Promise<void> {
    const telegramId = ctx.from?.id;
    const username = ctx.from?.username;

    if (!telegramId) {
      return;
    }

    const user = await UserModel.findOne({ telegramId });
    if (!user) {
      const newUser = new UserModel({
        telegramId,
        username,
      });
      await newUser.save();
    } else if (username && user.username !== username) {
      user.username = username;
      await user.save();
    }
  }

  private async showPaymentTypeSelection(ctx: BotContext): Promise<void> {
    try {
      // Check if user has agreed to terms before proceeding
      if (!ctx.session.hasAgreedToTerms) {
        await this.handleSubscribeCallback(ctx);
        return;
      }

      const keyboard = new InlineKeyboard().text(
        '🔄 Obuna | 30 kun bepul',
        'payment_type_subscription',
      );

      const message =
        "🎯 <b>30 kunlik bepul obuna</b>\n\n" +
        "Ajoyib! Sizga mosligi tekshirilgan paketni faollashtirish uchun pastdagi tugmani bosing.\n" +
        "Har 30 kunda to'lov avtomatik amalga oshiriladi, istalgan vaqtda bekor qilishingiz mumkin.";

      await ctx.editMessageText(message, {
        reply_markup: keyboard,
        parse_mode: 'HTML',
      });
    } catch (error) {
      await ctx.answerCallbackQuery(
        "To'lov turlarini ko'rsatishda xatolik yuz berdi.",
      );
    }
  }

  private async handleOneTimePayment(ctx: BotContext): Promise<void> {
    try {
      if (!ctx.session.hasAgreedToTerms) {
        await this.handleSubscribeCallback(ctx);
        return;
      }

      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId: telegramId });
      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      if (this.userHasActiveSubscription(user)) {
        const provider = await this.getLastSuccessfulProvider(
          user._id.toString(),
        );
        const message = this.getAlreadyPaidMessage(provider);

        await ctx.answerCallbackQuery({
          text: message,
          show_alert: true,
        } as any);
        await this.showMainMenu(ctx);
        return;
      }

      const selectedService = await this.selectedServiceChecker(ctx);

      const plan = await Plan.findOne({ selectedName: selectedService });
      if (!plan) {
        logger.error(`No plan found with selectedService: ${selectedService}`);
        await ctx.answerCallbackQuery(
          "To'lov rejasi topilmadi. Iltimos, administrator bilan bog'laning.",
          { show_alert: true },
        );
        return;
      }

      ctx.session.pendingOnetimePlanId = plan._id.toString();

      const keyboard = await this.getOneTimePaymentMethodKeyboard(
        ctx,
        plan,
        selectedService,
      );

      await ctx.editMessageText(
        "💰 <b>Bir martalik to'lov</b>\n\n" +
        "Iltimos, o'zingizga ma'qul to'lov turini tanlang:",
        {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        },
      );
    } catch (error) {
      await ctx.answerCallbackQuery(
        "To'lov turlarini ko'rsatishda xatolik yuz berdi.",
      );
    }
  }

  private async handleSubscriptionPayment(ctx: BotContext): Promise<void> {
    try {
      if (!ctx.session.hasAgreedToTerms) {
        await this.handleSubscribeCallback(ctx);
        return;
      }

      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId: telegramId });
      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      const userId = user._id as string;

      await this.selectedServiceChecker(ctx);

      const keyboard = await this.getSubscriptionPaymentMethodKeyboard(
        userId,
        ctx,
      );

      await ctx.editMessageText(
        "🔄 <b>Avtomatik to'lov (obuna)</b>\n\n" +
        "Iltimos, to'lov tizimini tanlang. Har 30 kunda to'lov avtomatik ravishda amalga oshiriladi:",
        {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        },
      );
    } catch (error) {
      await ctx.answerCallbackQuery(
        "To'lov turlarini ko'rsatishda xatolik yuz berdi.",
      );
    }
  }

  private async getOneTimePaymentMethodKeyboard(
    ctx: BotContext,
    _plan: IPlanDocument,
    selectedService: string,
  ) {
    if (!selectedService) {
      await ctx.answerCallbackQuery('Iltimos, avval xizmat turini tanlang.');
      await this.showMainMenu(ctx);
      return;
    }

    return new InlineKeyboard()
      .text("📲 Uzcard orqali to'lash", this.buildOneTimePaymentCallback('uzcard'))
      .row()
      .text("📲 Payme orqali to'lash", this.buildOneTimePaymentCallback('payme'))
      .row()
      .text("💳 Click orqali to'lash", this.buildOneTimePaymentCallback('click'))
      .row()
      .text('🔙 Asosiy menyu', 'main_menu');
  }

  private async getSubscriptionPaymentMethodKeyboard(
    userId: string,
    ctx: BotContext,
  ) {
    const selectedService = await this.selectedServiceChecker(ctx);

    const plan = await Plan.findOne({ selectedName: selectedService });

    if (!plan) {
      await ctx.answerCallbackQuery({
        text: "Obuna rejasi topilmadi. Iltimos, qayta urinib ko'ring.",
        show_alert: true,
      } as any);
      return new InlineKeyboard().text('🔙 Orqaga', 'back_to_payment_types');
    }

    const clickUrl =
      process.env.BASE_CLICK_URL +
      `?userId=${userId}&planId=${plan._id}&selectedService=${selectedService}`;

    const uzcardUrl =
      process.env.UZCARD_API_URL_SPORTS +
      `?userId=${userId}&planId=${plan._id}&selectedService=${selectedService}`;

    return new InlineKeyboard()
      .url('🏦 Uzcard/Humo (30 kun bepul)', uzcardUrl)
      .row()
      .url('💳 Click (30 kun bepul)', clickUrl)
      .row()
      .text('📲 Payme (30 kun bepul)', 'payme_subscription_unavailable')
      .row()
      .text('🔙 Orqaga', 'back_to_payment_types')
      .row()
      .text('🏠 Asosiy menyu', 'main_menu');
  }

  private userHasActiveSubscription(user: IUserDocument): boolean {
    if (!user.isActive || !user.subscriptionEnd) {
      return false;
    }

    const subscriptionEnd =
      user.subscriptionEnd instanceof Date
        ? user.subscriptionEnd
        : new Date(user.subscriptionEnd);

    return subscriptionEnd.getTime() > Date.now();
  }

  private async getLastSuccessfulProvider(
    userId: string,
  ): Promise<string | undefined> {
    const transaction = await Transaction.findOne({
      userId,
      status: TransactionStatus.PAID,
    })
      .sort({ createdAt: -1 })
      .exec();

    return transaction?.provider;
  }

  private getAlreadyPaidMessage(provider?: string): string {
    switch (provider) {
      case 'click':
        return "Siz Click orqali bir martalik to'lov qilgansiz. Obuna muddati tugagach qayta urinib ko'ring.";
      case 'payme':
        return "Siz Payme orqali bir martalik to'lov qilgansiz. Obuna muddati tugagach qayta urinib ko'ring.";
      case 'uzcard':
        return "Siz Uzcard orqali bir martalik to'lov qilgansiz. Obuna muddati tugagach qayta urinib ko'ring.";
      default:
        return "Sizda faol obuna mavjud. Obuna muddati tugagach qayta to'lov qilishingiz mumkin.";
    }
  }

  private buildOneTimePaymentCallback(
    provider: 'uzcard' | 'payme' | 'click',
  ): string {
    return `onetime|${provider}`;
  }

  private async handleOneTimePaymentProviderSelection(
    ctx: BotContext,
    provider: 'uzcard' | 'payme' | 'click',
  ): Promise<void> {
    const telegramId = ctx.from?.id;

    if (!telegramId) {
      await ctx.answerCallbackQuery(
        "Foydalanuvchi ma'lumotlari topilmadi. Iltimos, qayta urinib ko'ring.",
        { show_alert: true },
      );
      return;
    }

    const user = await UserModel.findOne({ telegramId }).exec();

    if (!user) {
      await ctx.answerCallbackQuery(
        "Foydalanuvchi ma'lumotlari topilmadi. Iltimos, qayta boshlang.",
        { show_alert: true },
      );
      return;
    }

    if (this.userHasActiveSubscription(user)) {
      await ctx.answerCallbackQuery(
        'Sizda allaqachon faol obuna mavjud. Yangi to‘lov talab qilinmaydi.',
        { show_alert: true },
      );
      return;
    }

    const selectedService = ctx.session.selectedService;

    if (!selectedService) {
      await ctx.answerCallbackQuery(
        'Iltimos, avval xizmat turini tanlang.',
        { show_alert: true },
      );
      await this.showMainMenu(ctx);
      return;
    }

    let plan: IPlanDocument | null = null;

    if (ctx.session.pendingOnetimePlanId) {
      plan = await Plan.findById(ctx.session.pendingOnetimePlanId).exec();
    }

    if (!plan) {
      plan = await Plan.findOne({ selectedName: selectedService }).exec();
      if (!plan) {
        await ctx.answerCallbackQuery(
          "To'lov rejasi topilmadi. Iltimos, administrator bilan bog'laning.",
          { show_alert: true },
        );
        return;
      }
      ctx.session.pendingOnetimePlanId = plan._id.toString();
    }

    const userId = user._id.toString();
    let redirectUrl: string | undefined;

    switch (provider) {
      case 'uzcard': {
        const baseUrl = process.env.BASE_UZCARD_ONETIME_URL;
        if (!baseUrl) {
          await ctx.answerCallbackQuery(
            "Uzcard to'lov havolasi sozlanmagan. Iltimos, administrator bilan bog'laning.",
            { show_alert: true },
          );
          return;
        }
        redirectUrl = `${baseUrl}/?userId=${userId}&planId=${plan._id}&selectedService=${selectedService}`;
        break;
      }
      case 'payme': {
        redirectUrl = generatePaymeLink({
          planId: plan._id.toString(),
          amount: plan.price,
          userId,
        });
        break;
      }
      case 'click': {
        const redirectURLParams: ClickRedirectParams = {
          userId,
          planId: plan._id.toString(),
          amount: plan.price as number,
        };
        redirectUrl = getClickRedirectLink(redirectURLParams);
        break;
      }
      default:
        await ctx.answerCallbackQuery(
          "Noma'lum to'lov turi tanlandi.",
          { show_alert: true },
        );
        return;
    }

    if (!redirectUrl) {
      await ctx.answerCallbackQuery(
        "To'lov havolasi tayyorlanmadi. Iltimos, administrator bilan bog'laning.",
        { show_alert: true },
      );
      return;
    }

    const providerTitles: Record<'uzcard' | 'payme' | 'click', string> = {
      uzcard: "📲 Uzcard orqali to'lash",
      payme: "📲 Payme orqali to'lash",
      click: "💳 Click orqali to'lash",
    };

    const keyboard = new InlineKeyboard()
      .url(providerTitles[provider], redirectUrl)
      .row()
      .text("🔄 To'lov turlariga qaytish", 'payment_type_onetime')
      .row()
      .text('🏠 Asosiy menyu', 'main_menu');

    try {
      await ctx.editMessageText(
        `${providerTitles[provider]} ni tanladingiz.\n\nQuyidagi tugma orqali to'lovni amalga oshirishingiz mumkin:`,
        {
          reply_markup: keyboard,
          disable_web_page_preview: true,
        },
      );
    } catch (error) {
      logger.warn('Failed to edit onetime payment message, sending new one', {
        error,
      });
      await ctx.reply(
        `${providerTitles[provider]} ni tanladingiz.\n\nQuyidagi tugma orqali to'lovni amalga oshirishingiz mumkin:`,
        {
          reply_markup: keyboard,
          disable_web_page_preview: true,
        },
      );
    }

    await ctx.answerCallbackQuery();
  }

  private async revokeUserInviteLink(
    user?: IUserDocument | null,
    save = true,
  ): Promise<void> {
    if (!user?.activeInviteLink) {
      return;
    }

    try {
      await this.bot.api.revokeChatInviteLink(
        config.CHANNEL_ID,
        user.activeInviteLink,
      );
      logger.info('Revoked existing invite link for user', {
        telegramId: user.telegramId,
      });
    } catch (error) {
      logger.warn('Failed to revoke invite link', {
        telegramId: user.telegramId,
        error,
      });
    }

    user.activeInviteLink = undefined;

    if (save) {
      try {
        await user.save();
      } catch (error) {
        logger.warn('Failed to save user after revoking invite link', {
          telegramId: user.telegramId,
          error,
        });
      }
    }
  }

  private async clearChatHistory(
    ctx: BotContext,
    fromMessageId?: number,
    limit = 30,
  ): Promise<void> {
    const chatId = ctx.chat?.id;
    const baseMessageId = fromMessageId ?? ctx.message?.message_id;

    if (!chatId || !baseMessageId || baseMessageId <= 1) {
      return;
    }

    for (let offset = 1; offset <= limit; offset++) {
      const targetMessageId = baseMessageId - offset;
      if (targetMessageId <= 0) {
        break;
      }

      try {
        await ctx.api.deleteMessage(chatId, targetMessageId);
      } catch (error: any) {
        const description: string | undefined = error?.description;

        if (
          description &&
          (description.includes("message can't be deleted") ||
            description.includes('message to delete not found') ||
            description.includes('bot was blocked by the user'))
        ) {
          continue;
        }

        logger.warn('Failed to delete message while clearing chat history', {
          chatId,
          targetMessageId,
          error,
        });
      }
    }
  }

  private async handleChatJoinRequest(ctx: BotContext): Promise<void> {
    const joinRequest = ctx.chatJoinRequest;
    if (!joinRequest) {
      return;
    }

    const telegramId = joinRequest.from.id;
    const chatId = joinRequest.chat.id;

    try {
      const user = await UserModel.findOne({ telegramId }).exec();

      if (user && this.userHasActiveSubscription(user)) {
        await ctx.api.approveChatJoinRequest(chatId, telegramId);
        logger.info('Join request approved', { telegramId, chatId });
        return;
      }

      await ctx.api.declineChatJoinRequest(chatId, telegramId);
      logger.info('Join request declined due to inactive subscription', {
        telegramId,
        chatId,
      });

      try {
        await ctx.api.sendMessage(
          telegramId,
          "❌ Obunangiz faol emas. Kanalga kirish uchun iltimos, obunani yangilang.",
        );
      } catch (error) {
        logger.warn('Failed to notify user about declined join request', {
          telegramId,
          error,
        });
      }
    } catch (error) {
      logger.error('Error processing join request', {
        telegramId,
        chatId,
        error,
      });
    }
  }

  private async handleAdminCommand(ctx: BotContext): Promise<void> {
    logger.info(`Admin command issued by user ID: ${ctx.from?.id}`);

    if (!this.ADMIN_IDS.includes(ctx.from?.id || 0)) {
      logger.info(`Authorization failed for ID: ${ctx.from?.id}`);
      return;
    }

    const totalUsers = await UserModel.countDocuments();
    const activeUsers = await UserModel.countDocuments({ isActive: true });

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const todayTimestamp = Math.floor(today.getTime() / 1000);

    const newUsersToday = await UserModel.countDocuments({
      _id: {
        $gt: new mongoose.Types.ObjectId(todayTimestamp),
      },
    });

    const newSubscribersToday = await UserModel.countDocuments({
      subscriptionStart: { $gte: today },
      isActive: true,
    });

    const expiredSubscriptions = await UserModel.countDocuments({
      isActive: false,
      subscriptionEnd: { $exists: true, $ne: null },
    });

    const threeDaysFromNow = new Date();
    threeDaysFromNow.setDate(threeDaysFromNow.getDate() + 3);

    const expiringIn3Days = await UserModel.countDocuments({
      subscriptionEnd: {
        $gte: new Date(),
        $lte: threeDaysFromNow,
      },
      isActive: true,
    });

    const neverSubscribed = await UserModel.countDocuments({
      $or: [
        { subscriptionStart: { $exists: false } },
        { subscriptionStart: null },
      ],
    });

    //Autosubscription qilinmadi keyin qilaman
    const totalCardStats = await UserCardsModel.aggregate([
      { $match: { verified: true } },
      {
        $group: {
          _id: '$cardType',
          count: { $sum: 1 },
        },
      },
    ]);

    const totalCards = totalCardStats.reduce((acc, cur) => acc + cur.count, 0);
    const totalCardBreakdown: Record<string, number> = {
      click: 0,
      uzcard: 0,
      payme: 0,
    };
    totalCardStats.forEach((stat) => {
      totalCardBreakdown[stat._id] = stat.count;
    });

    // Cards added today
    const todayCardStats = await UserCardsModel.aggregate([
      {
        $match: {
          verified: true,
          createdAt: { $gte: today },
        },
      },
      {
        $group: {
          _id: '$cardType',
          count: { $sum: 1 },
        },
      },
    ]);

    const todayCardTotal = todayCardStats.reduce(
      (acc, cur) => acc + cur.count,
      0,
    );
    const todayCardBreakdown: Record<string, number> = {
      click: 0,
      uzcard: 0,
      payme: 0,
    };
    todayCardStats.forEach((stat) => {
      todayCardBreakdown[stat._id] = stat.count;
    });

    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const completedSubscription = await UserCardsModel.countDocuments({
      verified: true,
      createdAt: { $gte: startOfDay },
    });

    //

    const statsMessage = `📊 <b>Bot statistikasi</b>: \n\n` +
      `👥 Umumiy foydalanuvchilar: ${totalUsers} \n` +
      `✅ Umumiy aktiv foydalanuvchilar: ${activeUsers} \n` +
      `🆕 Bugun botga start berganlar: ${newUsersToday} \n` +
      `💸 Bugun kanalga qo'shilgan foydalanuvchilar: ${newSubscribersToday} \n` +
      `📉 Obunasi tugaganlar: ${expiredSubscriptions} \n` +
      `⏳ Obunasi 3 kun ichida tugaydiganlar: ${expiringIn3Days} \n` +
      `🚫 Hech qachon obuna bo'lmaganlar: ${neverSubscribed} \n\n` +

      `📊 <b>Avtomatik to'lov statistikasi (bugun)</b>: \n\n` +
      `✅ Karta qo'shganlar: ${completedSubscription} \n\n` +

      `💳 <b>Qo'shilgan kartalar statistikasi</b>: \n\n` +
      `📦 Umumiy qo'shilgan kartalar: ${totalCards} \n` +
      ` 🔵 Uzcard: ${totalCardBreakdown.uzcard} \n` +
      ` 🟡 Click: ${totalCardBreakdown.click} \n` +
      ` 🟣 Payme: ${totalCardBreakdown.payme} \n\n` +
      `📅 <u>Bugun qo'shilgan kartalar</u>: ${todayCardTotal} \n` +
      ` 🔵 Uzcard: ${todayCardBreakdown.uzcard} \n` +
      ` 🟡 Click: ${todayCardBreakdown.click} \n` +
      ` 🟣 Payme: ${todayCardBreakdown.payme} \n\n\n`;

    try {
      // await ctx.reply('Admin command executed successfully.');
      await ctx.reply(statsMessage, {
        parse_mode: "HTML"
      })
    } catch (error) {
      logger.error('Error handling admin command:', error);
      await ctx.reply(
        '❌ Error processing admin command. Please try again later.',
      );
    }
  }


  private async handleDevTestSubscribe(ctx: BotContext): Promise<void> {
    try {
      const telegramId = ctx.from?.id;
      const user = await UserModel.findOne({ telegramId });
      if (!user) {
        await ctx.answerCallbackQuery(
          "Foydalanuvchi ID'sini olishda xatolik yuz berdi.",
        );
        return;
      }

      const plan = await Plan.findOne({
        name: 'Basic',
      });

      if (!plan) {
        logger.error('No plan found with name "Basic"');
        return;
      }

      try {
        const { user: subscription, wasKickedOut } =
          await this.subscriptionService.createSubscription(
            user._id as string,
            plan,
            ctx.from?.username,
          );

        if (wasKickedOut && telegramId) {
          await this.bot.api.unbanChatMember(config.CHANNEL_ID, telegramId);
        }

        await this.revokeUserInviteLink(subscription, false);

        const privateLink = await this.getPrivateLink();
        subscription.activeInviteLink = privateLink.invite_link;
        await subscription.save();
        const keyboard = new InlineKeyboard()
          .url('🔗 Kanalga kirish', privateLink.invite_link)
          .row()
          .text('🔙 Asosiy menyu', 'main_menu');

        let messageText =
          `🎉 DEV TEST: Muvaffaqiyatli obuna bo'ldingiz!\n\n` +
          `⏰ Obuna tugash muddati: ${subscription.subscriptionEnd.toLocaleDateString()}\n\n` +
          `[DEV MODE] To'lov talab qilinmadi\n\n`;

        if (wasKickedOut) {
          messageText += `ℹ️ Sizning avvalgi bloklanishingiz bekor qilindi. `;
        }

        messageText += `Quyidagi havola orqali kanalga kirishingiz mumkin:`;

        await ctx.editMessageText(messageText, {
          reply_markup: keyboard,
          parse_mode: 'HTML',
        });
      } catch (error) {
        if (
          error instanceof Error &&
          error.message === 'User already has an active subscription'
        ) {
          const keyboard = new InlineKeyboard()
            .text('📊 Obuna holati', 'check_status')
            .row()
            .text('🔙 Asosiy menyu', 'main_menu');

          await ctx.editMessageText(
            '⚠️ Siz allaqachon faol obunaga egasiz. Obuna holatini tekshirish uchun quyidagi tugmani bosing:',
            { reply_markup: keyboard },
          );
          return;
        }
        logger.error('Dev test subscription error:', error);
        await ctx.answerCallbackQuery(
          'Obunani tasdiqlashda xatolik yuz berdi.',
        );
      }
    } catch (error) {
      logger.error('Dev test subscription error:', error);
      await ctx.answerCallbackQuery(
        'Dev test obunasini yaratishda xatolik yuz berdi.',
      );
    }
  }

  private async selectedServiceChecker(ctx: BotContext) {
    const selectedService = ctx.session.selectedService;

    if (selectedService === undefined) {
      await ctx.answerCallbackQuery('Iltimos, avval xizmat turini tanlang.');
      await this.showMainMenu(ctx);
      return;
    }

    return selectedService;
  }


}

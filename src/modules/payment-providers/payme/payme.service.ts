import { Injectable } from '@nestjs/common';
import { TransactionMethods } from './constants/transaction-methods';
import { CheckPerformTransactionDto } from './dto/check-perform-transaction.dto';
import { RequestBody } from './types/incoming-request-body';
import { GetStatementDto } from './dto/get-statement.dto';
import { CancelTransactionDto } from './dto/cancel-transaction.dto';
import { PerformTransactionDto } from './dto/perform-transaction.dto';
import { CreateTransactionDto } from './dto/create-transaction.dto';
import { ErrorStatusCodes } from './constants/error-status-codes';
import { TransactionState } from './constants/transaction-state';
import { CheckTransactionDto } from './dto/check-transaction.dto';
import { PaymeError } from './constants/payme-error';
import { CancelingReasons } from './constants/canceling-reasons';
import logger from '../../../shared/utils/logger';
import { ValidationHelper } from '../../../shared/utils/validation.helper';
import { UserModel } from '../../../shared/database/models/user.model';
import { Plan } from '../../../shared/database/models/plans.model';
import {
  PaymentTypes,
  Transaction,
  TransactionStatus,
} from '../../../shared/database/models/transactions.model';
import { ConfigService } from '@nestjs/config';
import { BotService } from '../../bot/bot.service';

function hasActiveSubscription(user?: {
  isActive?: boolean;
  subscriptionEnd?: Date | null;
}): boolean {
  if (!user || !user.isActive || !user.subscriptionEnd) {
    return false;
  }

  const subscriptionEnd =
    user.subscriptionEnd instanceof Date
      ? user.subscriptionEnd
      : new Date(user.subscriptionEnd);

  return subscriptionEnd.getTime() > Date.now();
}

@Injectable()
export class PaymeService {
  constructor(
    private readonly configService: ConfigService,
    private readonly botService: BotService,
  ) { }

  async handleTransactionMethods(reqBody: RequestBody) {
    const method = reqBody.method;
    switch (method) {
      case TransactionMethods.CheckPerformTransaction:
        return await this.checkPerformTransaction(
          reqBody as CheckPerformTransactionDto,
        );

      case TransactionMethods.CreateTransaction:
        return await this.createTransaction(reqBody as CreateTransactionDto);

      case TransactionMethods.CheckTransaction:
        return await this.checkTransaction(
          reqBody as unknown as CheckTransactionDto,
        );

      case TransactionMethods.PerformTransaction:
        return await this.performTransaction(reqBody as PerformTransactionDto);

      case TransactionMethods.CancelTransaction:
        return await this.cancelTransaction(reqBody as CancelTransactionDto);

      case TransactionMethods.GetStatement:
        return await this.getStatement(reqBody as GetStatementDto);
      default:
        return 'Invalid transaction method';
    }
  }

  async checkPerformTransaction(
    checkPerformTransactionDto: CheckPerformTransactionDto,
  ) {
    const planId = checkPerformTransactionDto.params?.account?.plan_id;
    const userId = checkPerformTransactionDto.params?.account?.user_id;
    const selectedService =
      checkPerformTransactionDto.params?.account?.selected_service;

    if (selectedService) {
      logger.info(
        `Selected service in checkPerformTransaction: ${selectedService}`,
      );
    }

    if (!ValidationHelper.isValidObjectId(planId)) {
      return {
        error: {
          code: ErrorStatusCodes.TransactionNotAllowed,
          message: {
            uz: 'Sizda mahsulot/foydalanuvchi topilmadi',
            en: 'Product/user not found',
            ru: 'Товар/пользователь не найден',
          },
          data: null,
        },
      };
    }

    if (!ValidationHelper.isValidObjectId(userId)) {
      return {
        error: {
          code: ErrorStatusCodes.TransactionNotAllowed,
          message: {
            uz: 'Sizda mahsulot/foydalanuvchi topilmadi',
            en: 'Product/user not found',
            ru: 'Товар/пользователь не найден',
          },
          data: null,
        },
      };
    }

    const plan = await Plan.findById(planId).exec();
    const user = await UserModel.findById(userId).exec();

    if (!plan || !user) {
      return {
        error: {
          code: ErrorStatusCodes.TransactionNotAllowed,
          message: {
            uz: 'Sizda mahsulot/foydalanuvchi topilmadi',
            en: 'Product/user not found',
            ru: 'Товар/пользователь не найден',
          },
          data: null,
        },
      };
    }

    if (hasActiveSubscription(user)) {
      return {
        error: PaymeError.AlreadyDone,
      };
    }

    if (checkPerformTransactionDto.params.amount === plan.price) {
      return {
        result: {
          allow: true,
        },
      };
    }
    if (plan.price !== checkPerformTransactionDto.params.amount / 100) {
      console.log("Xato shuyerda bo'lishi mumkin");
      return {
        error: PaymeError.InvalidAmount,
      };
    }
    return {
      result: {
        allow: true,
      },
    };
  }

  async createTransaction(createTransactionDto: CreateTransactionDto) {
    const planId = createTransactionDto.params?.account?.plan_id;
    const userId = createTransactionDto.params?.account?.user_id;
    const transId = createTransactionDto.params?.id;

    const selectedService =
      createTransactionDto.params?.account?.selected_sport;

    if (selectedService) {
      logger.info(
        `Selected service in createTransaction: ${selectedService}`,
      );
    }

    if (!ValidationHelper.isValidObjectId(planId)) {
      return {
        error: PaymeError.ProductNotFound,
        id: transId,
      };
    }

    if (!ValidationHelper.isValidObjectId(userId)) {
      return {
        error: PaymeError.UserNotFound,
        id: transId,
      };
    }

    const plan = await Plan.findById(planId).exec();
    const user = await UserModel.findById(userId).exec();

    if (!user) {
      return {
        error: PaymeError.UserNotFound,
        id: transId,
      };
    }

    if (!plan) {
      return {
        error: PaymeError.ProductNotFound,
        id: transId,
      };
    }

    if (hasActiveSubscription(user)) {
      return {
        error: PaymeError.AlreadyDone,
        id: transId,
      };
    }

    if (createTransactionDto.params.amount / 100 !== plan.price) {
      console.log(
        'the amount in sum is: ',
        createTransactionDto.params.amount / 100,
      );
      return {
        error: PaymeError.InvalidAmount,
        id: transId,
      };
    }

    const existingTransaction = await Transaction.findOne({
      userId,
      planId,
      status: TransactionStatus.PENDING,
    }).exec();

    if (existingTransaction) {
      // Eski transactionning muddatini tekshirish
      const isExpired = this.checkTransactionExpiration(existingTransaction.createdAt);

      if (isExpired) {
        // Muddati tugagan transaction - bekor qilish
        await Transaction.findByIdAndUpdate(existingTransaction._id, {
          status: TransactionStatus.CANCELED,
          state: TransactionState.PendingCanceled,
          cancelTime: new Date(),
          reason: CancelingReasons.CanceledDueToTimeout,
        }).exec();

        logger.info(`Expired pending transaction ${existingTransaction.transId} cancelled`);
      } else if (existingTransaction.transId === transId) {
        return {
          result: {
            transaction: existingTransaction.id,
            state: TransactionState.Pending,
            create_time: new Date(existingTransaction.createdAt).getTime(),
          },
        };
      } else {
        return {
          error: PaymeError.TransactionInProcess,
          id: transId,
        };
      }
    }

    const transaction = await Transaction.findOne({ transId }).exec();

    if (transaction) {
      if (this.checkTransactionExpiration(transaction.createdAt)) {
        await Transaction.findOneAndUpdate(
          { transId },
          {
            status: 'CANCELED',
            cancelTime: new Date(),
            state: TransactionState.PendingCanceled,
            reason: CancelingReasons.CanceledDueToTimeout,
          },
        ).exec();

        return {
          error: {
            ...PaymeError.CantDoOperation,
            state: TransactionState.PendingCanceled,
            reason: CancelingReasons.CanceledDueToTimeout,
          },
          id: transId,
        };
      }

      return {
        result: {
          transaction: transaction.id,
          state: TransactionState.Pending,
          create_time: new Date(transaction.createdAt).getTime(),
        },
      };
    }

    const checkTransaction: CheckPerformTransactionDto = {
      method: TransactionMethods.CheckPerformTransaction,
      params: {
        amount: plan.price,
        account: {
          plan_id: planId,
          user_id: userId,
        },
      },
    };

    const checkResult = await this.checkPerformTransaction(checkTransaction);

    if (checkResult.error) {
      return {
        error: checkResult.error,
        id: transId,
      };
    }
    logger.info(`Selected sport before createTransaction: ${selectedService}`);

    const newTransaction = await Transaction.create({
      transId: createTransactionDto.params.id,
      userId: createTransactionDto.params.account.user_id,
      paymentType: PaymentTypes.ONETIME,
      planId: createTransactionDto.params.account.plan_id,
      provider: 'payme',
      state: TransactionState.Pending,
      amount: createTransactionDto.params.amount,
      selectedService: selectedService,
    });

    return {
      result: {
        transaction: newTransaction.id,
        state: TransactionState.Pending,
        create_time: new Date(newTransaction.createdAt).getTime(),
      },
    };
  }

  async performTransaction(performTransactionDto: PerformTransactionDto) {
    const transaction = await Transaction.findOne({
      transId: performTransactionDto.params.id,
    }).exec();

    if (!transaction) {
      return {
        error: PaymeError.TransactionNotFound,
        id: performTransactionDto.params.id,
      };
    }

    const user = await UserModel.findById(transaction.userId).exec();

    // Faqat subscription to'lovlari uchun aktiv obuna tekshiruvi
    // Onetime to'lovlar uchun bu tekshiruv o'tkazib yuboriladi
    // if (
    //   user &&
    //   hasActiveSubscription(user) &&
    //   transaction.status === TransactionStatus.PENDING
    // ) {
    //   await Transaction.findOneAndUpdate(
    //     { transId: performTransactionDto.params.id },
    //     {
    //       status: TransactionStatus.CANCELED,
    //       state: TransactionState.PendingCanceled,
    //       cancelTime: new Date(),
    //       reason: CancelingReasons.TransactionFailed,
    //     },
    //   ).exec();
    //
    //   return {
    //     error: {
    //       ...PaymeError.AlreadyDone,
    //       state: TransactionState.PendingCanceled,
    //       reason: CancelingReasons.TransactionFailed,
    //     },
    //     id: performTransactionDto.params.id,
    //   };
    // }

    if (transaction.status !== 'PENDING') {
      if (transaction.status !== 'PAID') {
        return {
          error: PaymeError.CantDoOperation,
          id: performTransactionDto.params.id,
        };
      }

      return {
        result: {
          state: transaction.state,
          transaction: transaction.id,
          perform_time: transaction.performTime
            ? new Date(transaction.performTime).getTime()
            : null,
        },
      };
    }

    const expirationTime = this.checkTransactionExpiration(
      transaction.createdAt,
    );

    if (expirationTime) {
      await Transaction.findOneAndUpdate(
        { transId: performTransactionDto.params.id },
        {
          status: 'CANCELED',
          cancelTime: new Date(),
          state: TransactionState.PendingCanceled,
          reason: CancelingReasons.CanceledDueToTimeout,
        },
      ).exec();

      return {
        error: {
          state: TransactionState.PendingCanceled,
          reason: CancelingReasons.CanceledDueToTimeout,
          ...PaymeError.CantDoOperation,
        },
        id: performTransactionDto.params.id,
      };
    }

    const performTime = new Date();

    const updatedPayment = await Transaction.findOneAndUpdate(
      { transId: performTransactionDto.params.id },
      {
        status: 'PAID',
        state: TransactionState.Paid,
        performTime,
      },
      { new: true },
    ).exec();

    const plan = await Plan.findById(transaction.planId).exec();

    if (!plan) {
      return {
        error: PaymeError.ProductNotFound,
        id: performTransactionDto.params.id,
      };
    }

    try {
      if (user) {
        user.subscriptionType = 'onetime';
        await user.save();

        await this.botService.handlePaymentSuccess(
          transaction.userId.toString(),
          user.telegramId,
          user.username,
        );
      }
    } catch (error) {
      logger.error('Error handling payment success:', error);
    }

    return {
      result: {
        transaction: updatedPayment?.id,
        perform_time: performTime.getTime(),
        state: TransactionState.Paid,
      },
    };
  }

  async cancelTransaction(cancelTransactionDto: CancelTransactionDto) {
    const transId = cancelTransactionDto.params.id;

    const transaction = await Transaction.findOne({ transId }).exec();

    if (!transaction) {
      return {
        id: transId,
        error: PaymeError.TransactionNotFound,
      };
    }

    if (transaction.status === 'PENDING') {
      const cancelTransaction = await Transaction.findByIdAndUpdate(
        transaction.id,
        {
          status: 'CANCELED',
          state: TransactionState.PendingCanceled,
          cancelTime: new Date(),
          reason: cancelTransactionDto.params.reason,
        },
        { new: true },
      ).exec();

      return {
        result: {
          cancel_time: cancelTransaction?.cancelTime?.getTime(),
          transaction: cancelTransaction?.id,
          state: TransactionState.PendingCanceled,
        },
      };
    }

    if (transaction.state !== TransactionState.Paid) {
      return {
        result: {
          state: transaction.state,
          transaction: transaction.id,
          cancel_time: transaction.cancelTime?.getTime(),
        },
      };
    }

    const updatedTransaction = await Transaction.findByIdAndUpdate(
      transaction.id,
      {
        status: 'CANCELED',
        state: TransactionState.PaidCanceled,
        cancelTime: new Date(),
        reason: cancelTransactionDto.params.reason,
      },
      { new: true },
    ).exec();

    return {
      result: {
        cancel_time: updatedTransaction?.cancelTime?.getTime(),
        transaction: updatedTransaction?.id,
        state: TransactionState.PaidCanceled,
      },
    };
  }

  async checkTransaction(checkTransactionDto: CheckTransactionDto) {
    const transaction = await Transaction.findOne({
      transId: checkTransactionDto.params.id,
    }).exec();

    if (!transaction) {
      return {
        error: PaymeError.TransactionNotFound,
        id: checkTransactionDto.params.id,
      };
    }

    return {
      result: {
        create_time: transaction.createdAt.getTime(),
        perform_time: transaction.performTime
          ? new Date(transaction.performTime).getTime()
          : 0,
        cancel_time: transaction.cancelTime
          ? new Date(transaction.cancelTime).getTime()
          : 0,
        transaction: transaction.id,
        state: transaction.state,
        reason: transaction.reason ?? null,
      },
    };
  }

  async getStatement(getStatementDto: GetStatementDto) {
    const transactions = await Transaction.find({
      createdAt: {
        $gte: new Date(getStatementDto.params.from),
        $lte: new Date(getStatementDto.params.to),
      },
      provider: 'payme',
    }).exec();

    return {
      result: {
        transactions: transactions.map((transaction) => {
          return {
            id: transaction.transId,
            time: new Date(transaction.createdAt).getTime(),
            amount: transaction.amount,
            account: {
              user_id: transaction.userId,
              planId: transaction.planId,
            },
            create_time: new Date(transaction.createdAt).getTime(),
            perform_time: transaction.performTime
              ? new Date(transaction.performTime).getTime()
              : 0,
            cancel_time: transaction.cancelTime
              ? new Date(transaction.cancelTime).getTime()
              : null,
            transaction: transaction.id,
            state: transaction.state,
            reason: transaction.reason || null,
          };
        }),
      },
    };
  }

  private checkTransactionExpiration(createdAt: Date) {
    const transactionCreatedAt = new Date(createdAt);
    const timeoutDuration = 15 * 60 * 1000; // 15 daqiqa (Payme standarti)
    const timeoutThreshold = new Date(Date.now() - timeoutDuration);

    return transactionCreatedAt < timeoutThreshold;
  }
}

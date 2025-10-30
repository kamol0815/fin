import mongoose, { Document, Schema } from 'mongoose';

export interface IUserCardsDocument extends Document {
  telegramId: number;
  username?: string;
  incompleteCardNumber: string;
  cardToken: string;
  expireDate: string;
  verificationCode?: number;
  verified: boolean;
  verifiedDate?: Date;
  userId: mongoose.Schema.Types.ObjectId;
  planId: mongoose.Schema.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
  deleteAt?: Date;
  cardType: CardType;

  UzcardIsTrusted?: boolean;
  UzcardBalance?: number;
  UzcardId?: number;
  UzcardOwner?: string;
  UzcardIncompleteNumber?: string;
  UzcardIdForDeleteCard?: number;

  subscribedTo?: SubscribedTo[];
}

export enum CardType {
  UZCARD = 'uzcard',
  CLICK = 'click',
  PAYME = 'payme',
}

export enum SubscribedTo {
  FOOTBALL = 'football',
  WRESTLING = 'wrestling',
}

const userCardsScheme = new Schema(
  {
    telegramId: { type: Number, required: true },
    username: { type: String },
    incompleteCardNumber: { type: String, required: false, unique: true },
    cardToken: { type: String, required: true, unique: true },
    expireDate: { type: String },
    verificationCode: { type: Number },
    verified: { type: Boolean, default: false },
    verifiedDate: { type: Date },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date },
    cardType: { type: String, enum: Object.values(CardType), required: true },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    planId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Plan',
      required: true,
    },

    UzcardIsTrusted: { type: Boolean, required: false },
    UzcardBalance: { type: Number, required: false },
    UzcardId: { type: Number, required: false },
    UzcardOwner: { type: String, required: false },
    UzcardIncompleteNumber: { type: String, required: false },
    UzcardIdForDeleteCard: { type: Number, required: false },

    subscribedTo: {
      type: [String], // Array of strings
      enum: Object.values(SubscribedTo),
      required: false,
      default: [], // Default to empty array
    },
  },
  {
    timestamps: true,
  },
);

// Indexes
userCardsScheme.index({ userId: 1 });
userCardsScheme.index({ planId: 1 });
userCardsScheme.index({ verified: 1 });
userCardsScheme.index({ verifiedDate: -1 });
userCardsScheme.index({ expireDate: 1 });
userCardsScheme.index({ userId: 1, verified: 1 });
// Compound unique index to allow only one card per user per payment provider type
userCardsScheme.index({ telegramId: 1, cardType: 1 }, { unique: true });

export const UserCardsModel = mongoose.model<IUserCardsDocument>(
  'UserCard',
  userCardsScheme,
);

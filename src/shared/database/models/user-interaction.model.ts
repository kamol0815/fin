import mongoose, { Document, Schema } from 'mongoose';

export enum InteractionEventType {
  INTRO_MENU = 'intro_menu',
  VIEW_INTRO_VIDEO = 'view_intro_video',
  VIEW_TERMS = 'view_terms',
  ACCEPT_TERMS = 'accept_terms',
  OPEN_UZCARD = 'open_uzcard',
}

export interface IUserInteractionDocument extends Document {
  telegramId: number;
  event: InteractionEventType;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

const userInteractionSchema = new Schema<IUserInteractionDocument>(
  {
    telegramId: {
      type: Number,
      required: true,
      index: true,
    },
    event: {
      type: String,
      enum: Object.values(InteractionEventType),
      required: true,
    },
    metadata: {
      type: Schema.Types.Mixed,
    },
  },
  {
    timestamps: true,
  },
);

userInteractionSchema.index({ telegramId: 1, event: 1, createdAt: -1 });

export const UserInteractionModel = mongoose.model<IUserInteractionDocument>(
  'UserInteraction',
  userInteractionSchema,
);

import mongoose, { Document } from 'mongoose';

export interface IUserSubscriptionDocument extends Document {
  user: mongoose.Schema.Types.ObjectId;
  plan: mongoose.Schema.Types.ObjectId;
  subscriptionType: 'subscription' | 'onetime';
  startDate: Date;
  endDate: Date;
  isActive: boolean;
  autoRenew: boolean;
  status: 'active' | 'expired' | 'cancelled' | 'pending';
  paidAmount: number;
  isTrial: boolean;
}

const userSubscriptionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    plan: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Plan',
      required: true,
    },
    subscriptionType: {
      type: String,
      enum: ['subscription', 'onetime'],
      required: true,
    },
    startDate: {
      type: Date,
      required: true,
      default: Date.now,
    },
    endDate: {
      type: Date,
      required: true,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    autoRenew: {
      type: Boolean,
      default: false,
    },
    status: {
      type: String,
      enum: ['active', 'expired', 'cancelled', 'pending'],
      default: 'active',
    },
    paidAmount: {
      type: Number,
      required: true,
    },
    isTrial: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  },
);

// Indexes for better query performance
userSubscriptionSchema.index({ user: 1, isActive: 1 });
userSubscriptionSchema.index({ endDate: 1 });
userSubscriptionSchema.index({ status: 1 });

export const UserSubscription = mongoose.model<IUserSubscriptionDocument>(
  'UserSubscription',
  userSubscriptionSchema,
);

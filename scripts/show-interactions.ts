import 'dotenv/config';
import mongoose from 'mongoose';
import { config } from '../src/shared/config';
import {
  InteractionEventType,
  UserInteractionModel,
} from '../src/shared/database/models/user-interaction.model';

type AggregatedUser = {
  telegramId: number;
  count: number;
  latest: Date;
};

type AggregatedEvent = {
  event: InteractionEventType;
  total: number;
  uniqueUsers: number;
  users: AggregatedUser[];
};

const EVENT_LABELS: Record<InteractionEventType, string> = {
  [InteractionEventType.INTRO_MENU]: "🚀 Menyuga o'tish (intro)",
  [InteractionEventType.VIEW_TERMS]: '📄 Foydalanish shartlari',
  [InteractionEventType.ACCEPT_TERMS]: '✅ Qabul qilaman',
  [InteractionEventType.OPEN_UZCARD]: '🎁 Uzcard/Humo havolasi',
};

function formatDate(date: Date): string {
  return date.toLocaleString();
}

async function fetchAggregatedStats(): Promise<AggregatedEvent[]> {
  const raw = await UserInteractionModel.aggregate([
    {
      $group: {
        _id: { event: '$event', telegramId: '$telegramId' },
        count: { $sum: 1 },
        latest: { $max: '$createdAt' },
      },
    },
    {
      $group: {
        _id: '$_id.event',
        total: { $sum: '$count' },
        uniqueUsers: { $sum: 1 },
        users: {
          $push: {
            telegramId: '$_id.telegramId',
            count: '$count',
            latest: '$latest',
          },
        },
      },
    },
    {
      $project: {
        _id: 0,
        event: '$_id',
        total: 1,
        uniqueUsers: 1,
        users: 1,
      },
    },
    {
      $sort: { event: 1 },
    },
  ]).exec();

  return raw as AggregatedEvent[];
}

function printSummary(stats: AggregatedEvent[]): void {
  console.log('\n=== Interaction Summary ===\n');
  for (const { event, total, uniqueUsers } of stats) {
    const label = EVENT_LABELS[event] ?? event;
    console.log(
      `${label}: ${uniqueUsers} ta foydalanuvchi, ${total} ta bosish`,
    );
  }
}

function printDetails(stats: AggregatedEvent[]): void {
  console.log('\n=== Batafsil maʼlumot ===\n');
  for (const { event, users } of stats) {
    const label = EVENT_LABELS[event] ?? event;
    console.log(`${label}:`);
    const sortedUsers = [...users].sort((a, b) => b.count - a.count);
    for (const user of sortedUsers) {
      console.log(
        `  • ${user.telegramId}: ${user.count} ta bosish (oxirgisi: ${formatDate(
          user.latest,
        )})`,
      );
    }
    console.log('');
  }
}

async function main() {
  try {
    await mongoose.connect(config.MONGODB_URI);
    const stats = await fetchAggregatedStats();

    if (!stats.length) {
      console.log('Hozircha hech qanday tugma statistikasi mavjud emas.');
      return;
    }

    printSummary(stats);
    printDetails(stats);
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((error) => {
  console.error('❌ Statistikani olishda xatolik:', error);
  process.exit(1);
});

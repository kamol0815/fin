import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { BotModule } from './modules/bot/bot.module';
import { ClickModule } from './modules/payment-providers/click/click.module';
import { PaymeModule } from './modules/payment-providers/payme/payme.module';
import { UzCardApiModule } from './modules/payment-providers/uzcard/uzcard.module';
import { UzcardOnetimeApiModule } from './modules/payment-providers/uzcard-onetime-api/uzcard-onetime-api.module';
import { ClickSubsApiModule } from './modules/payment-providers/click-subs-api/click-subs-api.module';
import { ClickOnetimeModule } from './modules/payment-providers/click-onetime/click-onetime.module';
import { PaymeSubsApiModule } from './modules/payment-providers/payme-subs-api/payme-subs-api.module';
import { PaymentLinkModule } from './modules/payment-link/payment-link.module';
import { SubscriptionManagementModule } from './modules/subscription-management/subscription-management.module';
import { LinksModule } from './modules/links/links.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    BotModule,
    ClickModule,
    PaymeModule,
    UzCardApiModule,
    UzcardOnetimeApiModule,
    ClickSubsApiModule,
    ClickOnetimeModule,
    PaymeSubsApiModule,
    PaymentLinkModule,
    SubscriptionManagementModule,
    LinksModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }

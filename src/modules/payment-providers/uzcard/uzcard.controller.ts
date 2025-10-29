import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Header,
  Post,
  Query,
  Render,
} from '@nestjs/common';
import { AddCardDto } from './dto/add-card.dto';
import { AddCardResponseDto } from './dto/response/add-card-response.dto';
import { ConfirmCardDto } from './dto/request/confirm-card.dto';
import { ErrorResponse, UzCardApiService } from './uzcard.service';
import { verifySignedToken } from '../../../shared/utils/signed-token.util';
import { config } from '../../../shared/config';
import { Plan } from '../../../shared/database/models/plans.model';

@Controller('uzcard-api')
export class UzCardApiController {
  constructor(private readonly uzCardApiService: UzCardApiService) {}

  @Get('/add-card')
  @Header('Content-Type', 'text/html')
  @Render('uzcard/payment-card-insert')
  async renderPaymentPage(@Query('token') token?: string) {
    if (!token) {
      throw new BadRequestException('Missing access token');
    }

    let payload: { uid: string; pid: string; svc: string };
    try {
      payload = verifySignedToken(token, config.PAYMENT_LINK_SECRET);
    } catch (error) {
      throw new BadRequestException('Invalid or expired access link');
    }

    const plan = await Plan.findById(payload.pid).lean();

    return {
      token,
      planName: plan?.name ?? 'Munajjim premium',
      selectedService: payload.svc,
    };
  }

  @Get('/uzcard-verify-sms')
  @Render('uzcard/sms-code-confirm')
  async renderSmsVerificationPage(
    @Query('session') session: string,
    @Query('phone') phone: string,
    @Query('token') token?: string,
  ) {
    if (!token) {
      throw new BadRequestException('Missing access token');
    }

    let payload: { uid: string; pid: string; svc: string };
    try {
      payload = verifySignedToken(token, config.PAYMENT_LINK_SECRET);
    } catch (error) {
      throw new BadRequestException('Invalid or expired access link');
    }

    const plan = await Plan.findById(payload.pid).lean();

    return {
      session,
      phone,
      token,
      planName: plan?.name ?? 'Munajjim premium',
      selectedService: payload.svc,
    };
  }

  @Post('/add-card')
  async addCard(
    @Body() requestBody: AddCardDto,
  ): Promise<AddCardResponseDto | ErrorResponse> { 
    return await this.uzCardApiService.addCard(requestBody);
  }

  @Post('/confirm-card')
  async confirmCard(@Body() requestBody: ConfirmCardDto) {
    try {
      return await this.uzCardApiService.confirmCard(requestBody);
    } catch (error) {
      // @ts-ignore
      return {
        success: false,
        // @ts-ignore
        errorCode: error.code || 'unknown_error',
        // @ts-ignore
        message:
          error.message ||
          "Kutilmagan xatolik yuz berdi. Iltimos qaytadan urinib ko'ring.",
      };
    }
  }

  @Get('resend-otp')
  async resendCode(
    @Query('session') session: string,
    @Query('token') token: string,
  ) {
    return await this.uzCardApiService.resendCode(session, token);
  }
}

import {
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

@Controller('uzcard-api')
export class UzCardApiController {
  constructor(private readonly uzCardApiService: UzCardApiService) {}

  @Get('/add-card')
  @Header('Content-Type', 'text/html')
  @Render('uzcard/payment-card-insert')
  renderPaymentPage(
    @Query('userId') userId: string,
    @Query('planId') planId: string,
    @Query('selectedService') selectedService: string,
  ) {
    return {
      userId,
      planId,
      selectedService,
    };
  }

  @Get('/uzcard-verify-sms')
  @Render('uzcard/sms-code-confirm')
  renderSmsVerificationPage(
    @Query('session') session: string,
    @Query('phone') phone: string,
    @Query('userId') userId: string,
    @Query('planId') planId: string,
    @Query('selectedService') selectedService: string,
  ) {
    return {
      session,
      phone,
      userId,
      planId,
      selectedService,
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
    @Query('userId') userId: string,
  ) {
    return await this.uzCardApiService.resendCode(session, userId);
  }
}

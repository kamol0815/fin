import { Controller, Post, Body, Get, Query, Res, Logger } from '@nestjs/common';
import { Response } from 'express';
import { ClickOnetimeService } from './click-onetime.service';

@Controller('click-onetime')
export class ClickOnetimeController {
    private readonly logger = new Logger(ClickOnetimeController.name);

    constructor(private readonly clickOnetimeService: ClickOnetimeService) { }

    /**
     * Click webhook - to'lov natijalarini qabul qiladi
     */
    @Post('/webhook')
    async handleClickWebhook(@Body() clickReqBody: any, @Res() res: Response) {
        try {
            this.logger.log(`Click webhook received: ${JSON.stringify(clickReqBody)}`);

            const response = await this.clickOnetimeService.handleClickCallback(clickReqBody);

            return res.json(response);
        } catch (error) {
            this.logger.error(`Error in Click webhook: ${error.message}`, error.stack);
            return res.json({
                error: -1,
                error_note: 'Internal server error'
            });
        }
    }

    /**
     * To'lov linkini generatsiya qilish
     */
    @Get('/generate-payment-link')
    async generatePaymentLink(
        @Query('userId') userId: string,
        @Query('planId') planId: string,
        @Query('amount') amount: string,
    ) {
        try {
            const paymentLink = this.clickOnetimeService.generatePaymentLink(userId, planId, amount);

            return {
                success: true,
                paymentLink
            };
        } catch (error) {
            this.logger.error(`Error generating payment link: ${error.message}`, error.stack);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

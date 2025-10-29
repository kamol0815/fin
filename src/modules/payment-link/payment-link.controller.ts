import { BadRequestException, Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { buildClickProviderUrl, ClickRedirectParams } from '../../shared/generators/click-redirect-link.generator';
import { buildPaymeProviderUrl, PaymeLinkGeneratorParams } from '../../shared/generators/payme-link.generator';
import { config } from '../../shared/config';
import { verifySignedToken } from '../../shared/utils/signed-token.util';

type RedirectPayload = ClickRedirectParams | PaymeLinkGeneratorParams;

@Controller('payment-link')
export class PaymentLinkController {
  @Get('click')
  redirectToClick(@Query('token') token: string, @Res() res: Response) {
    return res.redirect(this.resolveRedirectUrl(token, 'click'));
  }

  @Get('payme')
  redirectToPayme(@Query('token') token: string, @Res() res: Response) {
    return res.redirect(this.resolveRedirectUrl(token, 'payme'));
  }

  @Get('uzcard')
  redirectToUzcard(@Query('token') token: string, @Res() res: Response) {
    if (!token) {
      throw new BadRequestException('Missing redirect token');
    }

    try {
      verifySignedToken(token, config.PAYMENT_LINK_SECRET);
    } catch (error) {
      throw new BadRequestException('Invalid or expired redirect token');
    }

    return res.redirect(`/api/uzcard-api/add-card?token=${encodeURIComponent(token)}`);
  }

  private resolveRedirectUrl(token: string, provider: 'click' | 'payme'): string {
    if (!token) {
      throw new BadRequestException('Missing redirect token');
    }

    let payload: RedirectPayload;
    try {
      payload = verifySignedToken<RedirectPayload>(token, config.PAYMENT_LINK_SECRET);
    } catch (error) {
      throw new BadRequestException('Invalid or expired redirect token');
    }

    if (provider === 'click') {
      return buildClickProviderUrl(payload as ClickRedirectParams);
    }

    return buildPaymeProviderUrl(payload as PaymeLinkGeneratorParams);
  }
}

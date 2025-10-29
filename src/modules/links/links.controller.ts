import { Controller, Get, Header, Redirect } from '@nestjs/common';
import { config } from 'src/shared/config';

@Controller('links')
export class LinksController {
  @Get('terms')
  @Header('Cache-Control', 'no-cache')
  @Redirect(undefined, 302)
  redirectToTerms() {
    const target = config.SUBSCRIPTION_TERMS_URL?.trim();
    return {
      url: target || 'https://telegra.ph/Yulduzlar-Bashorati-Premium-OMMAVIY-OFERTA-06-26',
      statusCode: 302,
    };
  }
}

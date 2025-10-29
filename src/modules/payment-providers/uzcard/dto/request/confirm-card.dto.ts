import { IsNotEmpty } from 'class-validator';

export class ConfirmCardDto {
  @IsNotEmpty()
  session: string;

  @IsNotEmpty()
  otp: string;
  token: string;
}

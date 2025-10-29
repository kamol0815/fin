export class AddCardResponseDto {
  session?: number;
  otpSentPhone?: string;
  success: boolean;
  reusedCard?: boolean;
  message?: string;
}

import { Module } from '@nestjs/common';
import { ClickOnetimeController } from './click-onetime.controller';
import { ClickOnetimeService } from './click-onetime.service';

@Module({
    controllers: [ClickOnetimeController],
    providers: [ClickOnetimeService],
    exports: [ClickOnetimeService]
})
export class ClickOnetimeModule { }

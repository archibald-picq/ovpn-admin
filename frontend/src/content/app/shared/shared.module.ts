import { NgModule } from '@angular/core';
import {BytesPipe} from "./pipes/bytes.pipe";
import {BleService} from './services/ble/ble.service';

@NgModule({
  declarations: [
    BytesPipe,
  ],
  exports: [
    BytesPipe,
  ],
  providers: [
    BleService,
  ],
})
export class SharedModule {}

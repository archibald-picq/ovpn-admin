import { NgModule } from '@angular/core';
import {BytesPipe} from "./pipes/bytes.pipe";

@NgModule({
    declarations: [
        BytesPipe,
    ],
    exports: [
        BytesPipe,
    ],
})
export class SharedModule {}

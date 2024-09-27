import { NgModule, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterModule } from '@angular/router';
import {NotfoundPageComponent} from "./notfound/notfound.component";
import { NOTFOUND_ROUTES } from './error.route';
import { CommonModule } from '@angular/common';
import { DeniedPageComponent } from './denied/denied.component';
import { FatalPageComponent } from './fatal/fatal.component';
import {LoginComponent} from './login/login.component';
import {FormsModule} from '@angular/forms';

@NgModule({
    declarations: [
        NotfoundPageComponent,
        DeniedPageComponent,
        LoginComponent,
        FatalPageComponent,
    ],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule.forChild(NOTFOUND_ROUTES),
    ],
    schemas: [CUSTOM_ELEMENTS_SCHEMA]
})
export class ErrorModule {
    public static forRoot() {
        return {
            ngModule: ErrorModule,
        }
    }
}

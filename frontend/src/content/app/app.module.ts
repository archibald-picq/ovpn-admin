import { APP_INITIALIZER, LOCALE_ID, NgModule } from '@angular/core';
import {BrowserModule, Title} from '@angular/platform-browser';
import {httpInterceptorProviders} from './core/interceptor';
import {NgxWebstorageModule, SessionStorageService} from "ngx-webstorage";
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientModule} from "@angular/common/http";
import {MainComponent} from "./layouts/main/main.component";
import { RouterModule } from '@angular/router';
import { BusUiRoutingModule } from './app-routing.module';
import { CommonModule, registerLocaleData } from '@angular/common';
import localeFr from '@angular/common/locales/fr';
import { OpenvpnModule } from './openvpn/openvpn.module';
import { TopbarComponent } from './layouts/topbar/topbar.component';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { LoginComponent } from './layouts/login/login.component';
import { FormsModule } from '@angular/forms';
import { AppConfigService } from './shared/services/app-config.service';
import { RouterService } from './shared/services/router.service';
registerLocaleData(localeFr);

function initializeAppFactory(appInit: AppConfigService, routerService: RouterService): () => Promise<any> {
    routerService.setRouteErrorHandler();
    return () => appInit.Init();
}

@NgModule({
    declarations: [
        MainComponent,
        TopbarComponent,
        LoginComponent,
    ],
    imports: [
        CommonModule,
        BrowserModule,
        BrowserAnimationsModule,
        OpenvpnModule,
        BusUiRoutingModule,
        HttpClientModule,
        RouterModule,
        FormsModule,
        NgbModule,
        NgxWebstorageModule.forRoot({
            prefix: 'ovpn',
            separator: '-',
        }),
    ],
    providers: [
        AppConfigService,
        RouterService,
        {
            provide: APP_INITIALIZER,
            useFactory: initializeAppFactory,
            deps: [AppConfigService, RouterService],
            multi: true,
        },
        Title,
        {
            provide: LOCALE_ID,
            useValue: 'fr-FR',
        },
        httpInterceptorProviders,
    ],
    bootstrap: [MainComponent]
})
export class AppModule {
    constructor() {}
}

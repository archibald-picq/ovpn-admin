import { NgModule, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterModule } from '@angular/router';
import {OpenvpnClientsComponent} from "./clients/clients.component";
import { OPENVPN_ROUTES } from './openvpn.route';
import { MatSliderModule } from '@angular/material/slider';
import { MatSortModule } from '@angular/material/sort';
import { MatTableModule } from '@angular/material/table';
import { CommonModule } from '@angular/common';
import { OpenvpnService } from './services/openvpn.service';
import { EditClientComponent } from './modals/edit-client.component';
import { ConfirmRevokeClientCertificateComponent } from './modals/confirm-revoke-client-certificate.component';
import { FormsModule } from '@angular/forms';
import { CreateClientCertificateComponent } from './modals/create-client-certificate.component';
import { ConfirmDeleteClientCertificateComponent } from './modals/confirm-delete-client-certificate.component';
import { ConfirmRotateClientCertificateComponent } from './modals/confirm-rotate-client-certificate.component';
import { SharedModule } from '../shared/shared.module';
import { MatIconModule } from '@angular/material/icon';
import { NgbTooltipModule } from '@ng-bootstrap/ng-bootstrap';
import { OpenvpnSettingsPageComponent } from './settings/settings.component';
import { OpenvpnPreferencesPageComponent } from './preferences/preferences.component';
import { EditAdminAccountComponent } from './modals/edit-admin-account.component';
import { ConfirmDeleteAdminAccountComponent } from './modals/confirm-delete-admin-account.component';
import { UploadPageComponent } from './upload/upload.component';
import { LogPageComponent } from './log/log.component';
import { WebsocketService } from './services/websocket.service';
import {OpenvpnComponent} from "./openvpn.component";
import {ConfirmKillConnectionComponent} from "./modals/confirm-kill-connection.component";

@NgModule({
    declarations: [
        OpenvpnComponent,
        OpenvpnClientsComponent,
        EditClientComponent,
        ConfirmRevokeClientCertificateComponent,
        ConfirmDeleteClientCertificateComponent,
        ConfirmRotateClientCertificateComponent,
        CreateClientCertificateComponent,
        OpenvpnSettingsPageComponent,
        OpenvpnPreferencesPageComponent,
        EditAdminAccountComponent,
        ConfirmDeleteAdminAccountComponent,
        UploadPageComponent,
        LogPageComponent,
        ConfirmKillConnectionComponent,
    ],
    imports: [
        RouterModule.forChild(OPENVPN_ROUTES),
        CommonModule,
        MatSliderModule,
        MatSortModule,
        MatTableModule,
        FormsModule,
        SharedModule,
        MatIconModule,
        NgbTooltipModule,
    ],
    providers: [
        OpenvpnService,
        WebsocketService,
    ],
    schemas: [CUSTOM_ELEMENTS_SCHEMA]
})
export class OpenvpnModule {
    public static forRoot() {
        return {
            ngModule: OpenvpnModule,
        }
    }
}

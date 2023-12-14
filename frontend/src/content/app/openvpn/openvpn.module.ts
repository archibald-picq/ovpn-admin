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
import { MatMenuModule } from '@angular/material/menu';
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
import {ConfigPageComponent} from './config/config-page.component';
import {AddPackageComponent} from './config/modals/add-package.component';
import {ConfigureMasterServerComponent} from './config/modals/configure-master-server.component';
import {NetInterfaceComponent} from './config/components/net-interface.component';
import {MatButtonModule} from '@angular/material/button';
import {MatCardModule} from '@angular/material/card';
import {MatCheckboxModule} from '@angular/material/checkbox';
import {AccountService} from './services/account.service';
import {SetupComponent} from './setup/setup.component';
import {ChooseRoleComponent} from './setup/steps/choose-role.component';
import {CreateAccountComponent} from './setup/steps/create-account.component';
import {JoinMasterComponent} from './setup/steps/join-master.component';

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
        ConfigPageComponent,
        AddPackageComponent,
        ConfigureMasterServerComponent,
        NetInterfaceComponent,
        SetupComponent,
        ChooseRoleComponent,
        CreateAccountComponent,
        JoinMasterComponent,
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
        MatMenuModule,
        MatButtonModule,
        MatCheckboxModule,
        MatCardModule,
    ],
    providers: [
        OpenvpnService,
        WebsocketService,
        AccountService,
    ],
    schemas: [CUSTOM_ELEMENTS_SCHEMA],
})
export class OpenvpnModule {
    public static forRoot() {
        return {
            ngModule: OpenvpnModule,
        }
    }
}

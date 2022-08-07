import { NgModule, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterModule } from '@angular/router';
import {OpenvpnPageComponent} from "./openvpn.component";
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

@NgModule({
    declarations: [
        OpenvpnPageComponent,
        EditClientComponent,
        ConfirmRevokeClientCertificateComponent,
        ConfirmDeleteClientCertificateComponent,
        ConfirmRotateClientCertificateComponent,
        CreateClientCertificateComponent,
    ],
    imports: [
        CommonModule,
        RouterModule.forChild(OPENVPN_ROUTES),
        MatSliderModule,
        MatSortModule,
        MatTableModule,
        FormsModule,
    ],
    providers: [
        OpenvpnService,
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

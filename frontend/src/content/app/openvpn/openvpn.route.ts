import { Injectable } from '@angular/core';
import { Resolve, Route } from '@angular/router';
import { OpenvpnClientsComponent } from "./clients/clients.component";
import { OpenvpnService } from './services/openvpn.service';
import { IClientCertificate } from './models/client-certificate.interface';
import { Observable } from 'rxjs';
import { OpenvpnSettingsPageComponent } from './settings/settings.component';
import { OpenvpnConfig } from './models/openvpn-config.model';
import { AppConfigService } from '../shared/services/app-config.service';
import { OpenvpnPreferencesPageComponent } from './preferences/preferences.component';
import { UploadPageComponent } from './upload/upload.component';
import { LogPageComponent } from './log/log.component';
import { OpenvpnComponent } from './openvpn.component';

@Injectable({ providedIn: 'root' })
class ConfigResolve implements Resolve<OpenvpnConfig> {
    constructor(
        private readonly service: OpenvpnService,
        protected readonly appConfigService: AppConfigService,
    ) {}

    public resolve(): OpenvpnConfig|Observable<OpenvpnConfig> {
        const config = this.appConfigService.get();
        if (config.openvpn?.settings && config.openvpn?.preferences) {
            return config.openvpn;
        }
        return this.service.loadConfig();
    }
}

@Injectable({ providedIn: 'root' })
class ClientsResolve implements Resolve<IClientCertificate[]> {
    constructor(private readonly service: OpenvpnService) {}

    public resolve(): Observable<IClientCertificate[]> {
        return this.service.listClientCertificates();
    }
}

export const OPENVPN_ROUTES: Route[] = [{
    path: '',
    component: OpenvpnComponent,
    resolve: {
        config: ConfigResolve,
    },
    children: [
        {
            path: '',
            component: OpenvpnClientsComponent,
            resolve: {
                clients: ClientsResolve,
            },
        },
        {
            path: 'settings',
            component: OpenvpnSettingsPageComponent,
        },
        {
            path: 'preferences',
            component: OpenvpnPreferencesPageComponent,
        },
        {
            path: 'upload',
            component: UploadPageComponent,
        },
        {
            path: 'logs',
            component: LogPageComponent,
        },
    ],
}];

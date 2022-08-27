import { Injectable } from '@angular/core';
import { Resolve, Route } from '@angular/router';
import { OpenvpnPageComponent } from "./openvpn.component";
import { OpenvpnService } from './services/openvpn.service';
import { IClientCertificate } from './models/client-certificate.interface';
import { Observable } from 'rxjs';
import { OpenvpnSettingsPageComponent } from './settings/settings.component';
import { OpenvpnConfig } from './models/openvpn-config.model';
import { AppConfigService } from '../shared/services/app-config.service';
import { OpenvpnPreferencesPageComponent } from './preferences/preferences.component';

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
    resolve: {
        config: ConfigResolve,
    },
    children: [
        {
            path: '',
            component: OpenvpnPageComponent,
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
    ],
}];

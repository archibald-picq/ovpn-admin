import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, Resolve, Route } from '@angular/router';
import { OpenvpnClientsComponent } from "./clients/clients.component";
import { OpenvpnService } from './services/openvpn.service';
import { IClientCertificate } from './models/client-certificate.interface';
import { OpenvpnSettingsPageComponent } from './settings/settings.component';
import { OpenvpnConfig } from './models/openvpn-config.model';
import { OpenvpnPreferencesPageComponent } from './preferences/preferences.component';
import { UploadPageComponent } from './upload/upload.component';
import { LogPageComponent } from './log/log.component';
import { OpenvpnComponent } from './openvpn.component';
import {ConfigPageComponent} from './config/config-page.component';
import {NodeConfig} from './models/node-config.model';
import {SETUP_ROUTES} from './setup/setup.route';
import {IsConfigured} from './shared/resolver/is-configured.resolver';
import {IsNotConfigured} from './shared/resolver/is-not-configured.resolver';
import {SetupComponent} from './setup/setup.component';

@Injectable({ providedIn: 'root' })
class ConfigResolve implements Resolve<OpenvpnConfig> {
    constructor(
        private readonly service: OpenvpnService,
    ) {}

    public resolve(): Promise<OpenvpnConfig> {
        return this.service.loadConfig();
    }
}

@Injectable({ providedIn: 'root' })
class ClientsResolve implements Resolve<IClientCertificate[]> {
    constructor(private readonly service: OpenvpnService) {}

    public resolve(): Promise<IClientCertificate[]> {
        return this.service.listClientCertificates();
    }
}

@Injectable({providedIn: 'root'})
class ClientResolve implements Resolve<IClientCertificate|undefined> {
    constructor(private readonly service: OpenvpnService) {}

    public resolve(route: ActivatedRouteSnapshot): Promise<IClientCertificate|undefined> {
        return this.service.listClientCertificates().then(list => list.find(l => l.username === route.params.username));
    }
}

// /api/node/{nodeName}
@Injectable({providedIn: 'root'})
class NodeConfigResolve implements Resolve<NodeConfig> {
    constructor(private readonly service: OpenvpnService) {}

    public resolve(route: ActivatedRouteSnapshot): Promise<NodeConfig> {
        return this.service.getNodeConfig(route.params.username);
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
            canActivate: [
                IsConfigured,
            ],
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
        {
            path: 'config/:username',
            component: ConfigPageComponent,
            resolve: {
                client: ClientResolve,
                config: NodeConfigResolve,
            }
        },
        {
            path: 'setup',
            component: SetupComponent,
            canActivate: [
                IsNotConfigured,
            ],
            children: SETUP_ROUTES,
        }
    ],
}];

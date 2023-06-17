import { Injectable } from '@angular/core';
import {ActivatedRouteSnapshot, Resolve, Route} from '@angular/router';
import { OpenvpnClientsComponent } from "./clients/clients.component";
import { OpenvpnService } from './services/openvpn.service';
import { IClientCertificate } from './models/client-certificate.interface';
import {firstValueFrom, Observable} from 'rxjs';
import { OpenvpnSettingsPageComponent } from './settings/settings.component';
import { OpenvpnConfig } from './models/openvpn-config.model';
import { AppConfigService } from '../shared/services/app-config.service';
import { OpenvpnPreferencesPageComponent } from './preferences/preferences.component';
import { UploadPageComponent } from './upload/upload.component';
import { LogPageComponent } from './log/log.component';
import { OpenvpnComponent } from './openvpn.component';
import {ConfigPageComponent} from './config/config-page.component';
import {NodeConfig} from './models/node-config.model';

@Injectable({ providedIn: 'root' })
class ConfigResolve implements Resolve<OpenvpnConfig> {
    constructor(
        private readonly service: OpenvpnService,
        protected readonly appConfigService: AppConfigService,
    ) {}

    public resolve(): OpenvpnConfig|Observable<OpenvpnConfig> {
        const config = this.appConfigService.get();
        if ((config.openvpn?.settings && config.openvpn?.preferences) || config.openvpn?.unconfigured) {
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

@Injectable({providedIn: 'root'})
class ClientResolve implements Resolve<IClientCertificate|undefined> {
    constructor(private readonly service: OpenvpnService) {}

    public resolve(route: ActivatedRouteSnapshot): Promise<IClientCertificate|undefined> {
        return firstValueFrom(this.service.listClientCertificates()).then(list => list.find(l => l.username === route.params.username));
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
        }
    ],
}];

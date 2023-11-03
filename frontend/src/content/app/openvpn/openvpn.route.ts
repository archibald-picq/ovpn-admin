import { Injectable } from '@angular/core';
import {
    ActivatedRouteSnapshot,
    CanActivate,
    Resolve,
    Route, Router,
    RouterStateSnapshot,
    UrlTree
} from '@angular/router';
import { OpenvpnClientsComponent } from "./clients/clients.component";
import { OpenvpnService } from './services/openvpn.service';
import { IClientCertificate } from './models/client-certificate.interface';
import {Observable} from 'rxjs';
import { OpenvpnSettingsPageComponent } from './settings/settings.component';
import { OpenvpnConfig } from './models/openvpn-config.model';
import { OpenvpnPreferencesPageComponent } from './preferences/preferences.component';
import { UploadPageComponent } from './upload/upload.component';
import { LogPageComponent } from './log/log.component';
import { OpenvpnComponent } from './openvpn.component';
import {ConfigPageComponent} from './config/config-page.component';
import {NodeConfig} from './models/node-config.model';
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

@Injectable({
    providedIn: 'root',
})
export class IsConfigured implements CanActivate {
    constructor(
      private readonly service: OpenvpnService,
      private readonly router: Router,
    ) {
    }
    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean | UrlTree> | Promise<boolean | UrlTree> | boolean | UrlTree {
        return this.service.loadConfig().then((config) => {
            if (config.unconfigured) {
                return this.router.navigate(['./setup'] /* , {skipLocationChange: true}*/);
            }
            return true;
        });
    }
}

@Injectable({
    providedIn: 'root',
})
export class IsNotConfigured implements CanActivate {
    constructor(
      private readonly service: OpenvpnService,
      private readonly router: Router,
    ) {
    }
    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean | UrlTree> | Promise<boolean | UrlTree> | boolean | UrlTree {
        return this.service.loadConfig().then((config) => {
            if (!config.unconfigured) {
                return this.router.navigate(['./'] /* , {skipLocationChange: true}*/);
            }
            return true;
        });
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
        }
    ],
}];

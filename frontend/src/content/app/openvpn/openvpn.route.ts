import { Injectable } from '@angular/core';
import { Resolve, Route, Router } from '@angular/router';
import {OpenvpnPageComponent} from "./openvpn.component";
import { OpenvpnService } from './services/openvpn.service';
import { IClientCertificate } from './models/client-certificate.interface';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
class ClientsResolve implements Resolve<IClientCertificate[]> {
    constructor(private readonly service: OpenvpnService, private readonly router: Router) {}

    public resolve(): Observable<IClientCertificate[]> {
        return this.service.listClientCertificates();
    }
}

export const OPENVPN_ROUTES: Route[] = [{
    path: '',
    component: OpenvpnPageComponent,
    resolve: {
        clients: ClientsResolve,
    },
}];

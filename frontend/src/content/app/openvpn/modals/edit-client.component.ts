import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from "../models/client-certificate.interface";
import { OpenvpnService } from '../services/openvpn.service';

export class EditClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

export class Route {
    public address: string;
    public netmask: string;
    public description?: string;

    constructor(address: string, netmask: string, description?: string) {
        this.address = address;
        this.netmask = netmask;
        this.description = description;
    }

    public static parse(fromServer: Record<string, any>): Route {
        return new Route(fromServer.address ?? fromServer.Address, fromServer.netmask ?? fromServer.Mask, fromServer.description ?? fromServer.Description);
    }

    public clone(): Route {
        return new Route(this.address, this.netmask, this.description);
    }

    reset() {
        this.address = '';
        this.netmask = '';
        this.description = undefined;
    }
}

export class ClientConfig {
    public staticAddress: string;
    public pushRoutes: Route[] = [];
    public iRoutes: Route[] = [];

    constructor(staticAddress: string) {
        this.staticAddress = staticAddress;
    }

    public addPushRoute(route: Route): void {
        this.pushRoutes.push(route);
    }

    public addIRoute(route: Route): void {
        this.iRoutes.push(route);
    }

    public static parse(fromServer: Record<string, any>): ClientConfig {
        const config = new ClientConfig(fromServer.statisAddress ?? fromServer.ClientAddress);
        if (fromServer.CustomIRoutes) {
            fromServer.CustomIRoutes.forEach((route: Record<string, any>) => config.addIRoute(Route.parse(route)));
        }
        if (fromServer.CustomRoutes) {
            fromServer.CustomRoutes.forEach((route: Record<string, any>) => config.addPushRoute(Route.parse(route)));
        }
        return config;
    }

    public clone(): ClientConfig {
        const config = new ClientConfig(this.staticAddress);
        this.pushRoutes.forEach((route) => config.addPushRoute(route.clone()));
        this.iRoutes.forEach((route) => config.addIRoute(route.clone()));
        return config;
    }
}

@Component({
    selector: 'bus-openvpn-edit-client',
    templateUrl: './edit-client.component.html',
    styleUrls: ['./edit-client.component.scss'],
})
export class EditClientComponent {
    public model: ClientConfig;
    public certificate: IClientCertificate;
    public newPushRoute = new Route('', '');
    public newIRoute = new Route('', '');

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: EditClientOptions,
    ) {
        console.warn('options', this.options);
        this.certificate = this.options.client;
        this.model = this.options.client.ccd!.clone();
        if (this.model.staticAddress === 'dynamic') {
            this.model.staticAddress = '';
        }
        console.warn('this.model.staticAddress', this.model.staticAddress);
    }

    public removePushRoute(route: Route): void {
        const p = this.model.pushRoutes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.pushRoutes.splice(p, 1);
    }

    public removeIRoute(route: Route): void {
        const p = this.model.iRoutes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.iRoutes.splice(p, 1);
    }

    public addPushRoute(): void {
        this.model.pushRoutes.push(this.newPushRoute.clone());
        this.newPushRoute.reset();
    }

    public addIRoute(): void {
        this.model.iRoutes.push(this.newIRoute.clone());
        this.newIRoute.reset();
    }

    public clearFixedIp(): void {
        console.warn('clearFixedIp');
    }

    public async save(): Promise<void> {
        await this.openvpnService.saveClientConfig(this.options.client, this.model);
        this.options.client.ccd = this.model;
        this.modal.close('Save click');
    }
}
import { Component, Injector } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { OpenvpnService } from '../services/openvpn.service';
import { Settings } from '../models/openvpn-config.model';
import { Route } from '../models/route.model';


@Component({
    selector: 'bus-openvpn-settings',
    templateUrl: './settings.component.html',
    styleUrls: ['./settings.component.scss'],
})
export class OpenvpnSettingsPageComponent {
    public loading = false;
    public model: Settings;
    public original: Settings;
    public newRoutePush = new Route('', '');
    public newRoute = new Route('', '');
    public enableIpv4 = false;
    public enableIpv6 = false;
    public advertiseDnsIpv4 = false;
    public advertiseDnsIpv6 = false;
    public error = '';
    private serialized = '';

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
    ) {
        // console.warn('config', this.activatedRoute.parent?.snapshot.data.config);
        this.original = this.activatedRoute.parent?.snapshot.data.config.settings;
        console.warn('settings', this.original);
        this.model = this.original?.clone() ?? Settings.parse({});
        console.warn('routes', this.model.routes);
        console.warn('routesPush', this.model.routesPush);
        if (this.model.server) {
            this.enableIpv4 = true;
        }
        if (this.model.serverIpv6) {
            this.enableIpv6 = true;
        }
        if (this.model.dnsIpv4) {
            this.advertiseDnsIpv4 = true;
        }
        if (this.model.dnsIpv6) {
            this.advertiseDnsIpv6 = true;
        }
        this.serialized = JSON.stringify(this.toSave());
    }

    public removePushRoute(route: Route): void {
        const p = this.model.routesPush.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.routesPush.splice(p, 1);
    }

    public removeRoute(route: Route): void {
        const p = this.model.routes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.routes.splice(p, 1);
    }

    public addRoutePush(): void {
        this.model.routesPush.push(this.newRoutePush.clone());
        this.newRoutePush.reset();
    }

    public addRoute(): void {
        this.model.routes.push(this.newRoute.clone());
        this.newRoute.reset();
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';
            const toSave = this.toSave();
            await this.openvpnService.saveServiceConfig(this.model.serviceName, toSave);
            Object.assign(this.original, toSave);
            if (!toSave.dnsIpv4) {
                this.original.dnsIpv4 = '';
            }
            if (!toSave.dnsIpv6) {
                this.original.dnsIpv6 = '';
            }
            this.serialized = JSON.stringify(toSave);
            this.loading = false;
        } catch (e: any) {
            this.loading = false;
            this.error = e.error.message;
            console.warn('Error saving', e);
        }
    }

    private toSave(): Record<string, any> {
        return {
            ...this.enableIpv4? {
                server: this.model.server,
                forceGatewayIpv4: this.model.forceGatewayIpv4,
                forceGatewayIpv4ExceptDhcp: this.model.forceGatewayIpv4ExceptDhcp,
                forceGatewayIpv4ExceptDns: this.model.forceGatewayIpv4ExceptDns,
                ...this.advertiseDnsIpv4? {
                    dnsIpv4: this.model.dnsIpv4,
                }: {},
            }: {},
            ...this.enableIpv6? {
                serverIpv6: this.model.serverIpv6,
                forceGatewayIpv6: this.model.forceGatewayIpv6,
                ...this.advertiseDnsIpv6? {
                    dnsIpv6: this.model.dnsIpv6,
                }: {},
            }: {},
            compLzo: this.model.compLzo,
            enableMtu: this.model.enableMtu,
            tunMtu: parseInt(`${this.model.tunMtu}`, 10),
            duplicateCn: this.model.duplicateCn,
            clientToClient: this.model.clientToClient,
            routes: this.model.routes.map((route) => ({
                address: route.address,
                netmask: route.netmask,
                description: route.description,
            })),
            routesPush: this.model.routesPush.map((route) => ({
                address: route.address,
                netmask: route.netmask,
                description: route.description,
            })),
        };
    }

    public hasPendingChanges(): boolean {
        return this.serialized !== JSON.stringify(this.toSave());
    }
}

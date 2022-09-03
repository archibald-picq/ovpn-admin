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
    public newPush = new Route('', '');
    public newRoute = new Route('', '');
    public enableIpv4 = false;
    public enableIpv6 = false;
    public error = '';
    private serialized = '';

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
    ) {
        console.warn('config', this.activatedRoute.parent?.snapshot.data.config);
        this.original = this.activatedRoute.parent?.snapshot.data.config.settings;
        this.model = this.original.clone();
        // console.warn('this.model', this.model.routes);
        if (this.model.server) {
            this.enableIpv4 = true;
        }
        if (this.model.serverIpv6) {
            this.enableIpv6 = true;
        }
        this.serialized = JSON.stringify(this.toSave());
    }

    public removePush(route: Route): void {
        const p = this.model.pushs.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.pushs.splice(p, 1);
    }

    public removeRoute(route: Route): void {
        const p = this.model.routes.indexOf(route);
        if (p === -1) {
            console.warn('Error in page');
            return;
        }
        this.model.routes.splice(p, 1);
    }

    public addPush(): void {
        this.model.pushs.push(this.newPush.clone());
        this.newPush.reset();
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
            await this.openvpnService.saveServerConfig(toSave);
            Object.assign(this.original, toSave);
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
            }: {},
            ...this.enableIpv6? {
                serverIpv6: this.model.serverIpv6,
                forceGatewayIpv6: this.model.forceGatewayIpv6,
            }: {},
            compLzo: this.model.compLzo,
            duplicateCn: this.model.duplicateCn,
            routes: this.model.routes.map((route) => ({
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

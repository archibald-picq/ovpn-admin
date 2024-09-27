import { Component, Injector } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { OpenvpnService } from '../services/openvpn.service';
import {ApiKey, Preferences, Settings, User} from '../models/openvpn-config.model';
import { Sort } from '@angular/material/sort';
import { EditAdminAccountComponent, EditAdminAccountOptions } from '../modals/edit-admin-account.component';
import { MatTableDataSource } from '@angular/material/table';
import {
    ConfirmDeleteAdminAccountComponent,
    DeleteClientOptions
} from '../modals/confirm-delete-admin-account.component';
import {ConfirmDeleteApiKeyComponent, DeleteApiKeyOptions} from '../modals/confirm-delete-api-key.component';
import {EditApiKeyComponent, EditApiKeyOptions} from '../modals/edit-api-key.component';


@Component({
    selector: 'bus-openvpn-preferences',
    templateUrl: './preferences.component.html',
    styleUrls: ['./preferences.component.scss'],
})
export class OpenvpnPreferencesPageComponent {
    public loading = false;
    public serverInstanceConfig: Settings;
    public model: Preferences;
    public original: Preferences;
    public error = '';
    private serialized = '';
    public displayedColumns = ['username', 'name', 'actions'];
    public displayedColumnsApiKey = ['comment', 'expires', 'actions'];
    public sort?: Sort;
    public sortApiKey?: Sort;
    public dataSource = new MatTableDataSource<User>();
    public dataSourceApiKey = new MatTableDataSource<ApiKey>();
    public serverUrl = this.openvpnService.OPENVPN_ADMIN_API;

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
    ) {
        this.serverInstanceConfig = this.activatedRoute.parent?.snapshot.data.config.settings;
        this.original = this.activatedRoute.parent?.snapshot.data.config.preferences;
        this.dataSource.data = this.original.users;
        this.dataSourceApiKey.data = this.original.apiKeys;
        this.model = this.original.clone();
        this.serialized = JSON.stringify(this.toSave());
        if (this.serverUrl === '') {
            this.serverUrl = this.generateCurrentUrl();
        }
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';
            const toSave = this.toSave();
            await this.openvpnService.savePreferences(toSave);
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
            address: this.model.address,
            certificateDuration: parseInt(`${this.model.certificateDuration}`, 10),
            explicitExitNotify: this.model.explicitExitNotify,
            autoNoCache: this.model.authNoCache,
            verifyX509Name: this.model.verifyX509Name,
            allowAnonymousCsr: this.model.allowAnonymousCsr,
        };
    }

    public hasPendingChanges(): boolean {
        return this.serialized !== JSON.stringify(this.toSave());
    }

    public sortDataUsers(sort: Sort) {
        this.sort = sort;
        this.applySorting();
    }

    public sortDataApiKey(sort: Sort) {
        this.sortApiKey = sort;
        this.applySortingApiKey();
    }

    public async deleteUser(user: User): Promise<void> {
        try {
            await this.modalService.open(ConfirmDeleteAdminAccountComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: DeleteClientOptions,
                        useValue: new DeleteClientOptions(user),
                    }],
                    parent: this.injector,
                }),
            }).result;
            const p = this.dataSource.data.indexOf(user);
            if (p !== -1) {
                this.dataSource.data.splice(p, 1);
            } else {
                console.warn('Cant find user in list');
            }
            this.applySorting();
        } catch (e) {
            console.warn('Cancel create client', e);
        }
    }

    public async deleteApiKey(apiKey: ApiKey): Promise<void> {
        try {
            await this.modalService.open(ConfirmDeleteApiKeyComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: DeleteApiKeyOptions,
                        useValue: new DeleteApiKeyOptions(apiKey),
                    }],
                    parent: this.injector,
                }),
            }).result;
            const p = this.dataSourceApiKey.data.indexOf(apiKey);
            if (p !== -1) {
                console.warn('delete line', p);
                this.dataSourceApiKey.data.splice(p, 1);
            } else {
                console.warn('Cant find api key in list');
            }
            this.applySortingApiKey();
        } catch (e) {
            console.warn('Cancel delete api key', e);
        }
    }

    public async editUser(user: User): Promise<void> {
        try {
            await this.modalService.open(EditAdminAccountComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: EditAdminAccountOptions,
                        useValue: new EditAdminAccountOptions(user),
                    }],
                    parent: this.injector,
                }),
            }).result;
            this.applySorting();
        } catch (e) {
            console.warn('Cancel create client', e);
        }
    }


    public async editApiKey(apiKey: ApiKey): Promise<void> {
        try {
            await this.modalService.open(EditApiKeyComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: EditApiKeyOptions,
                        useValue: new EditApiKeyOptions(apiKey),
                    }],
                    parent: this.injector,
                }),
            }).result;
            this.applySortingApiKey();
        } catch (e) {
            console.warn('Cancel create api key', e);
        }
    }

    public async createUser(): Promise<void> {
        try {
            const newUser = await this.modalService.open(EditAdminAccountComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: EditAdminAccountOptions,
                        useValue: undefined,
                    }],
                    parent: this.injector,
                }),
            }).result;
            this.dataSource.data.push(newUser);
            this.applySorting();
        } catch (e) {
            console.warn('Cancel create client', e);
        }
    }

    public async createApiKey(): Promise<void> {
        try {
            const newApiKey = await this.modalService.open(EditApiKeyComponent, {
                centered: true,
                injector: Injector.create({
                    providers: [{
                        provide: EditApiKeyOptions,
                        useValue: undefined,
                    }],
                    parent: this.injector,
                }),
            }).result;
            this.dataSourceApiKey.data.push(newApiKey);
            this.applySortingApiKey();
        } catch (e) {
            console.warn('Cancel create api key', e);
        }
    }

    public applySorting(): void {
        if (this.sort) {
            this.dataSource.data.sort(this.sorter(this.sort));
        }
        this.dataSource.data = [...this.dataSource.data];
    }

    public applySortingApiKey(): void {
        if (this.sortApiKey) {
            this.dataSourceApiKey.data.sort(this.sorterApiKey(this.sortApiKey));
        }
        this.dataSourceApiKey.data = [...this.dataSourceApiKey.data];
    }

    private sorter(sort: Sort) {
        const rev1 = sort.direction === 'asc'? 1: -1;
        const rev2 = sort.direction === 'asc'? -1: 1;
        if (sort.active === 'username') {
            return (p1: User, p2: User) => {
                const a = p1.username ?? Infinity;
                const b = p2.username ?? Infinity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'name') {
            return (p1: User, p2: User) => {
                const a = p1.name ?? Infinity;
                const b = p2.name ?? Infinity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else {
            return (a: User, b: User) => a < b? rev1: (a > b? rev2: 0);
        }
    }

    private sorterApiKey(sort: Sort) {
        const rev1 = sort.direction === 'asc'? 1: -1;
        const rev2 = sort.direction === 'asc'? -1: 1;
        if (sort.active === 'name') {
            return (p1: ApiKey, p2: ApiKey) => {
                const a = p1.comment ?? Infinity;
                const b = p2.comment ?? Infinity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else if (sort.active === 'expires') {
            return (p1: ApiKey, p2: ApiKey) => {
                const a = p1.expires ?? Infinity;
                const b = p2.expires ?? Infinity;
                return a < b? rev1: (a > b? rev2: 0);
            };
        } else {
            return (a: ApiKey, b: ApiKey) => a < b? rev1: (a > b? rev2: 0);
        }
    }

    private generateCurrentUrl() {
        const port = ((document.location.protocol === 'https:' && document.location.port === '443') ||
          (document.location.protocol === 'http:' && document.location.port === '80'))? '': ':'+document.location.port;
        return document.location.protocol + '//'+document.location.hostname + port;
    }
}

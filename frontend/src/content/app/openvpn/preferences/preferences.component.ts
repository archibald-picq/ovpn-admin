import { Component, Injector } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { OpenvpnService } from '../services/openvpn.service';
import { Preferences, User } from '../models/openvpn-config.model';
import { Sort } from '@angular/material/sort';
import { EditAdminAccountComponent, EditAdminAccountOptions } from '../modals/edit-admin-account.component';
import { MatTableDataSource } from '@angular/material/table';
import {
    ConfirmDeleteAdminAccountComponent,
    DeleteClientOptions
} from '../modals/confirm-delete-admin-account.component';


@Component({
    selector: 'bus-openvpn-preferences',
    templateUrl: './preferences.component.html',
    styleUrls: ['./preferences.component.scss'],
})
export class OpenvpnPreferencesPageComponent {
    public loading = false;
    public model: Preferences;
    public original: Preferences;
    public error = '';
    private serialized = '';
    public displayedColumns = ['username', 'name', 'actions'];
    public sort?: Sort;
    public dataSource = new MatTableDataSource<User>();
    // public usersList: User[] = [];

    constructor(
        private readonly activatedRoute: ActivatedRoute,
        private readonly modalService: NgbModal,
        private readonly injector: Injector,
        private readonly openvpnService: OpenvpnService,
    ) {
        this.original = this.activatedRoute.snapshot.data.config.preferences;
        this.dataSource.data = this.original.users;
        this.model = this.original.clone();
        this.serialized = JSON.stringify(this.toSave());
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
            certificateDuration: parseInt(`${this.model.certificateDuration}`, 10),
            explicitExitNotify: this.model.explicitExitNotify,
            autoNoCache: this.model.authNoCache,
        };
    }

    public hasPendingChanges(): boolean {
        return this.serialized !== JSON.stringify(this.toSave());
    }

    public sortData(sort: Sort) {
        this.sort = sort;
        this.applySorting();
    }

    public async deleteUser(user: User): Promise<void> {
        try {
            await this.modalService.open(ConfirmDeleteAdminAccountComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: DeleteClientOptions,
                    useValue: new DeleteClientOptions(user),
                }], this.injector),
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

    public async editUser(user: User): Promise<void> {
        try {
            await this.modalService.open(EditAdminAccountComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: EditAdminAccountOptions,
                    useValue: new EditAdminAccountOptions(user),
                }], this.injector),
            }).result;
            this.applySorting();
        } catch (e) {
            console.warn('Cancel create client', e);
        }
    }

    public async createUser(): Promise<void> {
        try {
            const newUser = await this.modalService.open(EditAdminAccountComponent, {
                centered: true,
                injector: Injector.create([{
                    provide: EditAdminAccountOptions,
                    useValue: undefined,
                }], this.injector),
            }).result;
            this.dataSource.data.push(newUser);
            this.applySorting();
        } catch (e) {
            console.warn('Cancel create client', e);
        }
    }

    public applySorting(): void {
        if (this.sort) {
            this.dataSource.data.sort(this.sorter(this.sort));
        }
        this.dataSource.data = [...this.dataSource.data];
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
}

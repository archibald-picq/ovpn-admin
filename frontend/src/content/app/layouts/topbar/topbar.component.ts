import { Component } from '@angular/core';
import { NgbModal } from '@ng-bootstrap/ng-bootstrap';
import { LoginComponent } from '../login/login.component';
import { AppConfigService } from '../../shared/services/app-config.service';
import { UserService } from '../../shared/services/user.service';
import { AppConfig } from '../../shared/models/app-config';

@Component({
    selector: 'ovpn-topbar',
    templateUrl: './topbar.component.html',
    styleUrls: ['./topbar.scss'],
})
export class TopbarComponent {
    public isMenuCollapsed = false;
    public appConfig: AppConfig;
    constructor(
        private readonly modalService: NgbModal,
        private readonly appConfigService: AppConfigService,
        private readonly userService: UserService,
    ) {
        this.appConfig = this.appConfigService.get();
    }

    public async openLoginModal(): Promise<void> {
        try {
            console.warn('open modale', LoginComponent);
            await this.modalService.open(LoginComponent, {
                centered: true,
            }).result;
        } catch (e) {
            console.warn('Cancel auth', e);
        }
    }

    public async logout(): Promise<void> {
        try {
            await this.userService.logout();
        } catch (e) {
            console.warn('Error logout');
        }
    }
}

import {Component, Injector, Optional, Output} from '@angular/core';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { UserService } from '../../shared/services/user.service';
import { HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { RouterService } from '../../shared/services/router.service';
import {AppConfigService} from '../../shared/services/app-config.service';

@Component({
    selector: 'bus-login',
    templateUrl: './login.component.html',
    styleUrls: ['./login.component.scss'],
})
export class LoginComponent {
    public username = '';
    public password = '';
    public errorMessage = '';

    constructor(
        public readonly userService: UserService,
        public readonly router: Router,
        public readonly routerService: RouterService,
        public readonly configService: AppConfigService,
        @Optional() public readonly modal?: NgbActiveModal,
    ) {
    }

    public async login(): Promise<void> {
        console.warn('login');
        this.errorMessage = '';
        try {
            const userData = await this.userService.authenticate(this.username, this.password);
            await this.configService.reload();
            this.logginSucceed(userData);
            const currentUrl = this.routerService.getLastUrl();
            console.warn('reload url', currentUrl);
            this.router.navigateByUrl('/', {skipLocationChange: true}).then(() => {
                this.router.navigate([currentUrl]);
                this.modal?.close('success');
            });
        } catch (e: any) {
            if (e instanceof HttpErrorResponse) {
                this.errorMessage = e.error.message;
            }
            console.warn('Auth failed', e);
        }
    }

    private logginSucceed(userData: Record<string, any>): void {
        console.warn('just logged with', userData);
    }

    public cancel() {
        this.modal?.dismiss('Cross click');
    }
}

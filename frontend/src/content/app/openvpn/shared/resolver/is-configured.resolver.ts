import {Injectable} from '@angular/core';
import {CanActivate, Router} from '@angular/router';
import {OpenvpnService} from '../../services/openvpn.service';

@Injectable({
  providedIn: 'root',
})
export class IsConfigured implements CanActivate {
  constructor(
    private readonly service: OpenvpnService,
    private readonly router: Router,
  ) { }

  canActivate(): Promise<boolean> {
    return this.service.loadConfig().then((config) => {
      if (config.unconfigured) {
        return this.router.navigate(['./setup'] /* , {skipLocationChange: true}*/);
      }
      return true;
    });
  }
}

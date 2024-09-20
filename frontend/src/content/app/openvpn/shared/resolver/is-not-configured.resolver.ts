import {Injectable} from '@angular/core';
import {ActivatedRoute, CanActivate, Router} from '@angular/router';
import {OpenvpnService} from '../../services/openvpn.service';

@Injectable({
  providedIn: 'root',
})
export class IsNotConfigured implements CanActivate {
  public debugUi = document.cookie.indexOf('ovpnsetupdev=1')!==-1;

  constructor(
    private readonly service: OpenvpnService,
    private readonly router: Router,
    private readonly activatedRoute: ActivatedRoute,
  ) {
  }

  async canActivate(): Promise<boolean> {
    const config = await this.service.loadConfig();
    if (!config.unconfigured && !config.serverSetup && config.settings) {
      if (this.debugUi) {
        console.warn('nothing to configure, but stay here for debug');
        return true;
      } else {
        console.warn('nothing to configure, return to ../');
        return this.router.navigate(['./'], {relativeTo: this.activatedRoute /* skipLocationChange: true*/});
      }
    // } else if (config.caCertUnconfigured) {
    //   console.warn('navigate(./create-ca-cert)');
    //   return this.router.navigate(['./create-ca-cert'] /* , {skipLocationChange: true}*/);
    // } else if (config.serverCertUnconfigured) {
    //   console.warn('navigate(./create-server-cert)');
    //   return this.router.navigate(['./create-server-cert'] /* , {skipLocationChange: true}*/);
    }
    return true;
  }
}

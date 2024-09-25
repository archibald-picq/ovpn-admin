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

  async canActivate(): Promise<boolean> {
    const config = await this.service.loadConfig();
    // console.warn('config(unconfigured:', config.unconfigured,', serverSetup:', config.serverSetup, ')');

    // base configuration: create the admin account first
    if (config.unconfigured) {
      return this.router.navigate(['./setup'] /* , {skipLocationChange: true}*/);
    }
    if (config.serverSetup) {
      // console.warn("serverSetup");
      // return true;
      return this.router.navigate(['./setup/create-server'] /* , {skipLocationChange: true}*/);
    }
    // if (!config.settings) {
    //   console.warn("settings");
    //   // return true;
    //   return this.router.navigate(['./setup/create-server'] /* , {skipLocationChange: true}*/);
    // }
    return true;
  }
}

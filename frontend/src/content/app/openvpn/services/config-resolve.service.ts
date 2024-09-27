import {Injectable} from '@angular/core';
import {Resolve} from '@angular/router';
import {OpenvpnServiceConfig} from '../models/openvpn-config.model';
import {OpenvpnService} from './openvpn.service';

@Injectable({ providedIn: 'root' })
export class ConfigResolve implements Resolve<OpenvpnServiceConfig> {
  constructor(private readonly service: OpenvpnService) {}

  public resolve(): Promise<OpenvpnServiceConfig> {
    return this.service.loadConfig();
  }
}

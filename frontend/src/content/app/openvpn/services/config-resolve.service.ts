import {Injectable} from '@angular/core';
import {Resolve} from '@angular/router';
import {OpenvpnConfig} from '../models/openvpn-config.model';
import {OpenvpnService} from './openvpn.service';

@Injectable({ providedIn: 'root' })
export class ConfigResolve implements Resolve<OpenvpnConfig> {
  constructor(private readonly service: OpenvpnService) {}

  public resolve(): Promise<OpenvpnConfig> {
    return this.service.loadConfig();
  }
}

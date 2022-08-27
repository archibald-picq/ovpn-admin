import { OpenvpnConfig } from '../../openvpn/models/openvpn-config.model';
import { ServiceConfig } from './service-config';
import {UserProfile} from "./user-profile";


export class AppConfig {
  public color?: string;
  public user?: Record<string, any>;
  public openvpn?: OpenvpnConfig;
  public peripherals?: ServiceConfig;

  constructor(raw?: Record<string, any>) {
    if (raw) {
      this.import(raw);
    }
  }
  public static parse(raw: Record<string, any>): AppConfig {
    return new AppConfig(raw);
  }

  import(raw: Record<string, any>) {
    Object.assign(this, raw);
    if (raw.user) {
      this.user = UserProfile.parse(raw.user);
    }
    if (raw.openvpn) {
      this.openvpn = OpenvpnConfig.parse(raw.openvpn);
    }
  }
}
